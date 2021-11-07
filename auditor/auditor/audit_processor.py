import logging
import os
import re
import shutil
import tarfile
from decimal import Decimal
from fractions import Fraction
from tempfile import TemporaryDirectory
from typing import Dict, Generator, Iterable, Mapping, Type, TypeVar

import sqlalchemy
from common.constants import (
    BLOCKCHAIN_TIMESTAMP_EPSILON,
    CURRENCY_PRECISIONS,
    CURRENCY_TO_BLOCKCHAIN,
    MAX_USER_BAL,
    MAX_USER_BAL_BITS,
    SECP256K1_GENERATOR,
    SECP256K1_GROUP,
    Blockchain,
    Currency,
)
from common.utils.datetime import protobuf_to_datetime
from common.utils.uuid import bytes_to_uuid
from common.utils.zk import NIZK
from common.utils.zk.currency_conversion import verify_currency_conversion_commitment
from common.utils.zk.key_amount import verify_key_amount_commitment
from common.utils.zk.less_than_equal import verify_lte_commitment
from common.utils.zk.power_two import verify_power_two_commitment
from google.protobuf.message import DecodeError, Message
from hexbytes.main import HexBytes
from petlib.bn import Bn
from petlib.ec import EcPt
from protobufs.account_pb2 import AccountDeltaGroupChallengeRequest
from protobufs.audit_pb2 import Account as AccountPB2
from protobufs.audit_pb2 import AccountDeltaGroup as AccountDeltaGroupPB2
from protobufs.audit_pb2 import Audit as AuditPB2
from protobufs.audit_pb2 import CurrencyConversion
from protobufs.audit_pb2 import Key as KeyPB2
from protobufs.audit_pb2 import KeyAccount as KeyAccountPB2
from protobufs.audit_pb2 import KeyAccountLiability as KeyAccountLiabilityPB2
from protobufs.audit_pb2 import KeyCurrencyAsset as KeyCurrencyAssetPB2
from protobufs.audit_pb2 import SolvencyProof as SolvencyProofPB2
from protobufs.audit_pb2 import UserCumulativeLiability
from protobufs.audit_pb2 import UserKey as UserKeyPB2
from sqlalchemy import and_, desc, or_
from sqlalchemy.orm import Session

from auditor.exceptions import AuditProcessorFailedException
from auditor.sql.account import Account
from auditor.sql.account_delta import AccountDelta
from auditor.sql.account_delta_group import AccountDeltaGroup
from auditor.sql.audit import Audit
from auditor.sql.audit_user_cumulative_liability import AuditUserCumulativeLiability
from auditor.sql.audit_user_currency_liability import AuditUserCurrencyLiability
from auditor.sql.key import Key
from auditor.sql.key_account_commitment import KeyAccountCommitment
from auditor.sql.user_key import UserKey
from auditor.utils.blockchain_client.client import BlockchainClient
from auditor.utils.blockchain_client.vendor_base import TransactionNotFoundException
from auditor.utils.key_client import KeyClient
from auditor.utils.marketdata_client import MarketdataClient
from auditor.utils.profilers import record_auditor_latency
from auditor.utils.webauthn_client import AuthenticationFailedException, WebauthnClient

TMessage = TypeVar("TMessage", bound=Message)


AUDIT_SUBFOLDERS = (
    "accounts",
    "keys",
    "key_accounts",
    "account_delta_groups",
    "key_currency_assets",
    "key_account_liabilities",
    "user_keys",
    "user_cumulative_liability",
)

PATH_REGEX = re.compile(
    r"^audit/(audit.bin|solvency_proof.bin|(" + r"|".join(AUDIT_SUBFOLDERS) + r")/[0-9A-Za-z\-]*.bin)$"
)

LOGGER = logging.getLogger(__name__)


class AuditProcessor:
    def __init__(
        self,
        key_client: KeyClient,
        webauthn_client: WebauthnClient,
        blockchain_client: BlockchainClient,
        marketdata_client: MarketdataClient,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        acceptable_exchange_rate_epsilon: Decimal,
        audit_folder: str,
    ) -> None:
        self._key_client = key_client
        self._webauthn_client = webauthn_client
        self._blockchain_client = blockchain_client
        self._marketdata_client = marketdata_client
        self._sessionmaker = sessionmaker
        self._acceptable_exchange_rate_epsilon = acceptable_exchange_rate_epsilon
        self._audit_folder = audit_folder

    @staticmethod
    def _safe_extract(audit_tarfile: str, audit_dest_folder: str) -> None:
        with TemporaryDirectory() as tempdir:
            with tarfile.open(audit_tarfile, "r") as tarfile_descriptor:
                file_members = tarfile_descriptor.getmembers()
                for file_member in file_members:
                    file_path = file_member.path
                    normalized_file_path = os.path.normpath(file_path)
                    if PATH_REGEX.match(normalized_file_path) is None:
                        continue
                    tarfile_descriptor.extract(file_member, path=tempdir, set_attrs=False)
            shutil.move(tempdir, audit_dest_folder)

    @staticmethod
    def _get_block_number(currency: Currency, audit: Audit) -> int:
        if currency == Currency.BTC:
            return audit.bitcoin_block
        if currency in (Currency.ETH, Currency.GUSD):
            return audit.ethereum_block
        raise ValueError("Invalid currency")

    @staticmethod
    def _load_protobuf_from_file(message_type: Type[TMessage], filepath: str) -> TMessage:
        message = message_type()
        with open(filepath, "rb") as f:
            try:
                message.ParseFromString(f.read())
                return message
            except DecodeError as e:
                raise AuditProcessorFailedException(
                    f"Unable to load protobuf {filepath} into message of type {type(message)}"
                ) from e

    def _yield_protobufs_from_folder(  # pylint: disable=inconsistent-return-statements
        self, message_type: Type[TMessage], folder: str
    ) -> Generator[TMessage, None, None]:
        if not os.path.exists(folder):
            return None
        for filepath in os.listdir(folder):
            if filepath.endswith(".bin"):
                yield self._load_protobuf_from_file(message_type, os.path.join(folder, filepath))

    def add_audit_metadata(self, session: Session, audit_metadata_pb: AuditPB2) -> Audit:
        """
        1. Add the audit metadata to the audit table. Validate that the bitcoin and ethereum blocks
        are both at least as big as the last audit, and that the audit number is monotonically increasing.
        """
        latest_bitcoin_block = self._blockchain_client.get_latest_block_number_from_chain(Blockchain.BTC)
        latest_ethereum_block = self._blockchain_client.get_latest_block_number_from_chain(Blockchain.ETH)
        previous_audit = session.query(Audit).order_by(desc(Audit.version_number)).first()
        if previous_audit is None:
            if audit_metadata_pb.auditVersion != 1:
                raise AuditProcessorFailedException("First audit must have version 1")
        else:
            if audit_metadata_pb.auditVersion != previous_audit.version_number + 1:
                raise AuditProcessorFailedException(
                    f"Audit version number {audit_metadata_pb.auditVersion} != "
                    f"previous_audit number {previous_audit.version_number} + 1"
                )
            if not previous_audit.finished:
                raise AuditProcessorFailedException("previous audit not finished")
            if audit_metadata_pb.bitcoinBlock < previous_audit.bitcoin_block:
                raise AuditProcessorFailedException(
                    f"Bitcoin block in audit {audit_metadata_pb.bitcoinBlock} < "
                    f"previous audit bitcoin block {previous_audit.bitcoin_block}"
                )

            if audit_metadata_pb.ethereumBlock < previous_audit.ethereum_block:
                raise AuditProcessorFailedException(
                    f"Ethereum block in audit {audit_metadata_pb.ethereumBlock} < "
                    f"previous audit ethereum block {previous_audit.ethereum_block}"
                )

        if audit_metadata_pb.bitcoinBlock > latest_bitcoin_block:
            raise AuditProcessorFailedException(
                f"Bitcoin block in audit {audit_metadata_pb.bitcoinBlock} is ahead "
                f"of chain height {latest_bitcoin_block}"
            )
        if audit_metadata_pb.ethereumBlock > latest_ethereum_block:
            raise AuditProcessorFailedException(
                f"Ethereum block in audit {audit_metadata_pb.ethereumBlock} is ahead "
                f"of chain height {latest_ethereum_block}"
            )
        new_audit = Audit(
            version_number=audit_metadata_pb.auditVersion,
            bitcoin_block=audit_metadata_pb.bitcoinBlock,
            ethereum_block=audit_metadata_pb.ethereumBlock,
            timestamp=protobuf_to_datetime(audit_metadata_pb.timestamp),
            base_currency=Currency[audit_metadata_pb.baseCurrency],
            exchange_rates=audit_metadata_pb.exchangeRates,
        )
        session.add(new_audit)
        return new_audit

    def add_new_user_keys(self, session: Session, audit_data_location: str, audit: Audit) -> None:
        """
        2. Process all new user keys. Ensure that there does not exist any
        existing user key for each user in user keys
        (since right now users can only have one key). Load into the user_keys table.
        """
        for new_user_key in self._yield_protobufs_from_folder(
            UserKeyPB2, os.path.join(audit_data_location, "user_keys")
        ):
            if audit.version_number != new_user_key.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            # the database ensures that there is only one key per user since the user_uuid is defined as a unique field
            session.add(
                UserKey(
                    user_key_uuid=bytes_to_uuid(new_user_key.keyId),
                    credential_id=HexBytes(new_user_key.credentialId),
                    user_uuid=bytes_to_uuid(new_user_key.userId),
                    public_key=HexBytes(new_user_key.publicKey),
                    credential_type=new_user_key.credentialType,
                    audit_publish_version=audit.version_number,
                )
            )

    def import_new_keys(self, session: Session, audit_data_location: str, audit: Audit) -> None:
        """
        3. Import all new keys via self._key_client.track_new_deposit_key()
        """
        for new_key in self._yield_protobufs_from_folder(KeyPB2, os.path.join(audit_data_location, "keys")):
            if audit.version_number != new_key.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            self._key_client.track_deposit_key(
                session=session,
                key_uuid=bytes_to_uuid(new_key.keyId),
                public_key=EcPt.from_binary(new_key.publicKey, group=SECP256K1_GROUP),
                permuted_public_key=EcPt.from_binary(new_key.permutedPublicKey, group=SECP256K1_GROUP),
                permutation_nizk=NIZK.deserialize(new_key.permutationNIZK),
                ownership_nizk=NIZK.deserialize(new_key.assetOwnershipNIZK),
                ownership_commitment=EcPt.from_binary(new_key.assetOwnershipCommitment, group=SECP256K1_GROUP),
                audit_version=new_key.auditVersion,
            )

    def import_new_accounts(self, session: Session, audit_data_location: str, audit: Audit) -> None:
        """
        4. Import all new accounts by adding a row to the Account table
        """
        for new_account in self._yield_protobufs_from_folder(AccountPB2, os.path.join(audit_data_location, "accounts")):
            if audit.version_number != new_account.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            session.add(
                Account(
                    uuid=bytes_to_uuid(new_account.accountId),
                    account_type=new_account.accountType,
                    user_uuid=bytes_to_uuid(new_account.userId),
                    currency=Currency[new_account.currency],
                    audit_version=new_account.auditVersion,
                )
            )

    def import_new_deposit_key_accounts(self, session: Session, audit_data_location: str, audit: Audit) -> None:
        """
        5. Import all new deposit key accounts via self._key_client.track_deposit_key_account()
        """
        for new_deposit_key_account in self._yield_protobufs_from_folder(
            KeyAccountPB2, os.path.join(audit_data_location, "key_accounts")
        ):
            if audit.version_number != new_deposit_key_account.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            self._key_client.track_deposit_key_account(
                session=session,
                key_uuid=bytes_to_uuid(new_deposit_key_account.keyId),
                account_uuid=bytes_to_uuid(new_deposit_key_account.accountId),
                ownership_commitment=EcPt.from_binary(new_deposit_key_account.ownershipCommitment, SECP256K1_GROUP),
                ownership_nizk=NIZK.deserialize(new_deposit_key_account.ownershipNIZK),
                block_number=new_deposit_key_account.blockNumber,
                audit_version=new_deposit_key_account.auditVersion,
            )

    def process_new_blocks(self, bitcoin_block: int, ethereum_block: int) -> None:
        """
        6. For each blockchain, call blockchain_client.process_block() for the block after the last processed block
        for the blockchain through the block number (inclusive) specified in the audit metadata.
        """
        last_bitcoin_block = self._blockchain_client.get_latest_processed_block_number(Blockchain.BTC)
        if last_bitcoin_block is None:
            last_bitcoin_block = self._blockchain_client.get_start_block_number(Blockchain.BTC) - 1
        last_ethereum_block = self._blockchain_client.get_latest_processed_block_number(Blockchain.ETH)
        if last_ethereum_block is None:
            last_ethereum_block = self._blockchain_client.get_start_block_number(Blockchain.ETH) - 1

        for bitcoin_block_number in range(last_bitcoin_block + 1, bitcoin_block + 1):
            self._blockchain_client.process_block(blockchain=Blockchain.BTC, block_number=bitcoin_block_number)

        for ethereum_block_number in range(last_ethereum_block + 1, ethereum_block + 1):
            self._blockchain_client.process_block(blockchain=Blockchain.ETH, block_number=ethereum_block_number)

    def process_account_delta_groups(self, session: Session, audit_data_location: str, audit: Audit) -> None:
        """
        7. For all exchanges and withdrawals:
            a. Validate the webauthn signature self._webauthn_client.validate_assertion_response().
                If validation fails, abort.
            b. In the case of withdrawals, validate that each unsigned blockchain transaction was recorded on-chain
                via self._blockchain_client.validate_tx_in_chain(). If any transaction fails validation, abort.
            c. Record the account_deltas in the account_delta_group and account_delta_table
            d. Accumulate the account_delta_commitment by (user, currency) in the audit_user_currency_liability table.
        """

        for account_delta_group_pb in self._yield_protobufs_from_folder(
            AccountDeltaGroupPB2, os.path.join(audit_data_location, "account_delta_groups")
        ):
            if audit.version_number != account_delta_group_pb.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            try:
                user_uuid, account_delta_group_challenge_request = self._webauthn_client.validate_assertion_response(
                    session=session,
                    challenge_request=account_delta_group_pb.challengeRequest,
                    challenge_type=account_delta_group_pb.challengeRequest.challengeType,
                    response=account_delta_group_pb.assertion,
                    audit_version=audit.version_number,
                    challenge_request_payload_type=AccountDeltaGroupChallengeRequest,
                )
            except AuthenticationFailedException as e:
                raise AuditProcessorFailedException("failed to validate account delta group signature") from e

            for tx_id, tx in zip(account_delta_group_pb.txnIds, account_delta_group_challenge_request.transactions):
                try:
                    self._blockchain_client.validate_tx_in_chain(
                        blockchain=Blockchain[tx.blockchain], txn_hash=HexBytes(tx_id), tx_params=tx.txParams
                    )
                except TransactionNotFoundException as e:
                    raise AuditProcessorFailedException(
                        f"Transaction id {tx_id.hex()} on blockchain {tx.blockchain} not found in chain"
                    ) from e

            account_delta_group_uuid = bytes_to_uuid(account_delta_group_pb.id)
            session.add(
                AccountDeltaGroup(
                    uuid=account_delta_group_uuid,
                    user_uuid=bytes_to_uuid(account_delta_group_pb.userId),
                    challenge_uuid=bytes_to_uuid(account_delta_group_pb.challengeRequest.nonce),
                    audit_publish_version=audit.version_number,
                )
            )
            for commitment in account_delta_group_challenge_request.commitments:
                currency_commitment = EcPt.from_binary(commitment.commitment, SECP256K1_GROUP)
                session.add(
                    AccountDelta(
                        account_delta_group_uuid=account_delta_group_uuid,
                        account_uuid=bytes_to_uuid(commitment.accountId),
                        commitment=currency_commitment,
                    )
                )
                account = (
                    session.query(Account)
                    .filter(Account.uuid == bytes_to_uuid(commitment.accountId), Account.user_uuid == user_uuid)
                    .one()
                )
                currency = account.currency
                audit_user_currency_liability = (
                    session.query(AuditUserCurrencyLiability)
                    .filter(
                        AuditUserCurrencyLiability.audit_version == audit.version_number,
                        AuditUserCurrencyLiability.user_uuid == user_uuid,
                        AuditUserCurrencyLiability.currency == currency,
                    )
                    .populate_existing()
                    .with_for_update()
                    .one_or_none()
                )
                if audit_user_currency_liability is None:
                    previous_user_audit_currency_liability = (
                        session.query(AuditUserCurrencyLiability).filter(
                            AuditUserCurrencyLiability.audit_version == audit.version_number - 1,
                            AuditUserCurrencyLiability.user_uuid == user_uuid,
                            AuditUserCurrencyLiability.currency == currency,
                        )
                    ).one_or_none()

                    # check in case there isn't a current commitment for previous audit
                    # (e.g. if this is the currency for the user)
                    if previous_user_audit_currency_liability is None:
                        cumulative_account_delta_commitment = EcPt(SECP256K1_GROUP)
                    else:
                        cumulative_account_delta_commitment = (
                            previous_user_audit_currency_liability.cumulative_account_delta_commitment
                        )
                    audit_user_currency_liability = AuditUserCurrencyLiability(
                        audit_version=audit.version_number,
                        user_uuid=user_uuid,
                        currency=currency,
                        cumulative_account_delta_commitment=cumulative_account_delta_commitment + currency_commitment,
                    )
                    session.add(audit_user_currency_liability)
                    session.flush()  # populate defaults
                    continue
                audit_user_currency_liability.cumulative_account_delta_commitment += currency_commitment

    def compute_deposit_liability_commitments(self, session: Session, audit_data_location: str, audit: Audit) -> None:
        """
        8. Compute the total liabilities by running protocol 1 in provisions for each entry in KeyAccountCommitment.
        Accumulate in the audit_user_currency_liability table
        """
        # loading from the database as it is important that we have a commitment for every key account liability
        # in the audit otherwise the institution could be failing to credit funds to customers
        results = (
            session.query(KeyAccountCommitment, Key, Account)
            .filter(
                Key.key_uuid == KeyAccountCommitment.key_uuid,
                Account.uuid == KeyAccountCommitment.account_uuid,
                or_(
                    *[
                        and_(
                            Account.currency == currency,
                            KeyAccountCommitment.block_number
                            < self._get_block_number(
                                currency, audit
                            ),  # key is only valid starting with the following block
                        )
                        for currency in Currency
                    ]
                ),
            )
            .all()
        )
        LOGGER.info("Number of keys expected key account commitments: %d", len(results))

        for key_account_commitment, key, account in results:
            key_account_liability_filename = os.path.join(
                audit_data_location,
                "key_account_liabilities",
                f"{key_account_commitment.key_uuid.hex}-{key_account_commitment.account_uuid.hex}.bin",
            )
            key_account_liability = self._load_protobuf_from_file(
                KeyAccountLiabilityPB2, key_account_liability_filename
            )
            if audit.version_number != key_account_liability.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")

            currency = account.currency
            from_block = key_account_commitment.block_number + 1  # commitment is valid after this block number
            to_block = self._get_block_number(currency, audit)
            cumulative_deposit_amount = self._blockchain_client.get_cumulative_deposits(
                key_uuid=bytes_to_uuid(key_account_liability.keyId),
                currency=currency,
                from_block_number=from_block,
                to_block_number=to_block,
            )
            amount = Bn.from_decimal(str(int(cumulative_deposit_amount * CURRENCY_PRECISIONS[currency])))
            permuted_public_key = key.permuted_secp256k1_public_key
            ownership_commitment = key_account_commitment.commitment
            balance_commitment = EcPt.from_binary(key_account_liability.p, SECP256K1_GROUP)

            verify_key_amount_commitment(
                amount=amount,
                y=permuted_public_key,
                p=balance_commitment,
                l=ownership_commitment,
                key_amount_nizk=NIZK.deserialize(key_account_liability.nizk),
                bit_commitment_nizk=key_account_commitment.nizk,
            )
            audit_user_currency_liability = (
                session.query(AuditUserCurrencyLiability)
                .filter(
                    AuditUserCurrencyLiability.audit_version == audit.version_number,
                    AuditUserCurrencyLiability.user_uuid == account.user_uuid,
                    AuditUserCurrencyLiability.currency == currency,
                )
                .populate_existing()
                .with_for_update()
                .one_or_none()
            )
            if audit_user_currency_liability is None:
                previous_user_audit_currency_liability = (
                    session.query(AuditUserCurrencyLiability).filter(
                        AuditUserCurrencyLiability.audit_version == audit.version_number - 1,
                        AuditUserCurrencyLiability.user_uuid == account.user_uuid,
                        AuditUserCurrencyLiability.currency == currency,
                    )
                ).one_or_none()

                # check in case there isn't a current commitment for previous audit
                # (e.g. if this is the currency for the user)
                if previous_user_audit_currency_liability is None:
                    cumulative_account_delta_commitment = EcPt(SECP256K1_GROUP)
                else:
                    cumulative_account_delta_commitment = (
                        previous_user_audit_currency_liability.cumulative_account_delta_commitment
                    )
                audit_user_currency_liability = AuditUserCurrencyLiability(
                    audit_version=audit.version_number,
                    user_uuid=account.user_uuid,
                    currency=currency,
                    cumulative_account_delta_commitment=cumulative_account_delta_commitment,
                    cumulative_deposit_commitment=balance_commitment,
                )
                session.add(audit_user_currency_liability)
                session.flush()  # populate defaults
                continue
            audit_user_currency_liability.cumulative_deposit_commitment += balance_commitment

    def compute_user_cumulative_liability_commitments(
        self, session: Session, audit: Audit, audit_data_location: str
    ) -> EcPt:
        """
        9. For every user in the Audit User Currency Liability table, expect a user_cumulative_liability protobuf
           Validate the currency conversion nizk (adjusting for the isNegative field if needed)
           Store in the AuditUserCumulativeLiability table (and the currency conversions in the
           AuditUserCurrencyLiability) table
           If the user balance is positive, then accumulate the base currency commitment and return
        """
        cumulative_liabilities_base_currency = EcPt(SECP256K1_GROUP)
        for (user_uuid,) in (
            session.query(AuditUserCurrencyLiability.user_uuid)
            .filter(AuditUserCurrencyLiability.audit_version == audit.version_number)
            .distinct()
        ):
            user_cumulative_liability_filename = os.path.join(
                audit_data_location,
                "user_cumulative_liability",
                f"{user_uuid.hex}.bin",
            )
            user_cumulative_liability = self._load_protobuf_from_file(
                UserCumulativeLiability, user_cumulative_liability_filename
            )
            if audit.version_number != user_cumulative_liability.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            audit_user_currency_liabilities = (
                session.query(AuditUserCurrencyLiability)
                .filter(
                    AuditUserCurrencyLiability.audit_version == audit.version_number,
                    AuditUserCurrencyLiability.user_uuid == user_uuid,
                )
                .populate_existing()
                .with_for_update()
                .all()
            )
            session.flush()
            currency_to_commitment: Dict[Currency, EcPt] = {}
            currency_to_currency_conversion: Dict[Currency, CurrencyConversion] = {}
            for currency_conversion in user_cumulative_liability.liabilityCurrencyConversions:
                if audit.version_number != currency_conversion.auditVersion:
                    raise AuditProcessorFailedException("audit version mismatch")
                currency_to_currency_conversion[Currency[currency_conversion.fromCurrency]] = currency_conversion
            for audit_user_currency_liability in audit_user_currency_liabilities:
                currency = audit_user_currency_liability.currency
                from_commitment = (
                    audit_user_currency_liability.cumulative_account_delta_commitment
                    + audit_user_currency_liability.cumulative_deposit_commitment
                )
                currency_conversion = currency_to_currency_conversion[currency]
                currency_to_commitment[currency] = from_commitment
                to_currency_commitment = EcPt.from_binary(currency_conversion.toCurrencyCommitment, SECP256K1_GROUP)
                nizk = NIZK.deserialize(currency_conversion.nizk)
                assert audit_user_currency_liability.to_currency_commitment is None
                assert audit_user_currency_liability.to_currency_nizk is None
                audit_user_currency_liability.to_currency_commitment = to_currency_commitment
                audit_user_currency_liability.to_currency_nizk = nizk
                session.flush()
            user_commitment = self._convert_to_base_currency_commitment(
                audit, user_cumulative_liability.liabilityCurrencyConversions, currency_to_commitment
            )
            cumulative_nizk = NIZK.deserialize(user_cumulative_liability.nizk)
            verify_power_two_commitment(
                user_commitment
                + (
                    MAX_USER_BAL * SECP256K1_GENERATOR
                    if user_cumulative_liability.isNegative
                    else EcPt(SECP256K1_GROUP)
                ),
                MAX_USER_BAL_BITS,
                cumulative_nizk,
            )
            session.add(
                AuditUserCumulativeLiability(
                    audit_version=audit.version_number,
                    user_uuid=user_uuid,
                    cumulative_base_currency_commitment=user_commitment,
                    is_negative=user_cumulative_liability.isNegative,
                    nizk=cumulative_nizk,
                )
            )
            session.flush()
            if not user_cumulative_liability.isNegative:
                cumulative_liabilities_base_currency += user_commitment
        return cumulative_liabilities_base_currency

    def compute_total_assets(self, session: Session, audit_data_location: str, audit: Audit) -> Mapping[Currency, EcPt]:
        """
        10. Validate the asset commitments included in the audit, and reduce the commitments to a total commitment by
            the currency
        """
        currency_to_asset_commitment: Dict[Currency, EcPt] = {}

        for key_currency_asset in self._yield_protobufs_from_folder(
            KeyCurrencyAssetPB2, os.path.join(audit_data_location, "key_currency_assets")
        ):
            if audit.version_number != key_currency_asset.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            key_uuid = bytes_to_uuid(key_currency_asset.keyId)
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            address = key.get_address(blockchain=CURRENCY_TO_BLOCKCHAIN[Currency[key_currency_asset.currency]])
            currency = Currency[key_currency_asset.currency]
            block_number = self._get_block_number(currency, audit)
            amount = self._blockchain_client.get_balance_from_chain(
                session=session,
                address=address,
                currency=Currency[key_currency_asset.currency],
                block_metadata=self._blockchain_client.get_block_metadata_from_chain(
                    blockchain=CURRENCY_TO_BLOCKCHAIN[currency],
                    block_number=block_number,
                ),
            )
            balance_commitment = EcPt.from_binary(key_currency_asset.p, SECP256K1_GROUP)
            # verify key_currency_asset nizk before adding to cumulative
            verify_key_amount_commitment(
                amount=Bn.from_decimal(str(int(amount * CURRENCY_PRECISIONS[currency]))),
                y=key.permuted_secp256k1_public_key,
                p=balance_commitment,
                l=key.ownership_commitment,
                key_amount_nizk=NIZK.deserialize(key_currency_asset.nizk),
                bit_commitment_nizk=key.ownernship_nzik,
            )
            if currency in currency_to_asset_commitment:
                currency_to_asset_commitment[currency] += balance_commitment
            else:
                currency_to_asset_commitment[currency] = balance_commitment
        return currency_to_asset_commitment

    def validate_exchange_rates(self, audit: Audit) -> None:
        """
        11. Validate that the audit metadata exchange rates are reasonable. You can do this by querying the gemini API
            for historical marketdata or using the compound.finance price feed api:
            https://compound.finance/docs/prices
        """
        epsilon = self._acceptable_exchange_rate_epsilon

        audit_timestamp = audit.timestamp

        for exchange_rate in audit.exchange_rates.exchangeRates:
            expected_exchange_rate = self._marketdata_client.get_quote_at_timestamp(
                from_currency=Currency[exchange_rate.currency],
                to_currency=audit.base_currency,
                timestamp=audit_timestamp,
            )
            if abs(Decimal(exchange_rate.rate) / Decimal(expected_exchange_rate) - 1) > epsilon:
                raise AuditProcessorFailedException("exchange rate too far from expected")

    @staticmethod
    def _convert_to_base_currency_commitment(  # type: ignore[misc]
        audit: Audit,
        currency_conversions: Iterable[CurrencyConversion],
        currency_to_commitment: Mapping[Currency, EcPt],
    ) -> EcPt:
        """
        12/13: Validate that the cumulative commitments in steps 9 and 10 are the same as the fromCommitments
               in the solvency proof currency commitment
        """
        total = EcPt(SECP256K1_GROUP)
        currency_to_currency_conversion: Dict[Currency, CurrencyConversion] = {}
        for currency_conversion in currency_conversions:
            if audit.version_number != currency_conversion.auditVersion:
                raise AuditProcessorFailedException("audit version mismatch")
            currency_to_currency_conversion[Currency[currency_conversion.fromCurrency]] = currency_conversion
        currency_to_exchange_rate: Dict[Currency, Fraction] = {}
        for exchange_rate in audit.exchange_rates.exchangeRates:
            currency = Currency[exchange_rate.currency]
            assert currency not in currency_to_exchange_rate
            currency_to_exchange_rate[currency] = Fraction(exchange_rate.rate)
        for currency in Currency:
            if currency not in currency_to_commitment and currency not in currency_to_currency_conversion:
                continue
            currency_conversion = currency_to_currency_conversion[currency]
            if currency in currency_to_commitment:
                commitment = currency_to_commitment[currency]
            else:
                commitment = EcPt(SECP256K1_GROUP)
            from_currency_commitment = EcPt.from_binary(currency_conversion.fromCurrencyCommitment, SECP256K1_GROUP)
            if commitment != from_currency_commitment:
                raise AuditProcessorFailedException(
                    f"From currency commitment in currency conversion != calculated currency"
                    f"commitment for currency {currency}"
                )
            to_currency = Currency[currency_conversion.toCurrency]
            if to_currency != audit.base_currency:
                raise AuditProcessorFailedException(
                    f"To currency {currency_conversion.toCurrency} for from currency of {currency} != "
                    f"audit base currency currency {audit.base_currency}"
                )
            to_currency_commitment = EcPt.from_binary(currency_conversion.toCurrencyCommitment, SECP256K1_GROUP)
            rate = currency_to_exchange_rate[currency]
            nizk = NIZK.deserialize(currency_conversion.nizk)
            verify_currency_conversion_commitment(
                from_currency_commitment, to_currency_commitment, currency, to_currency, rate, nizk
            )
            total += to_currency_commitment
        return total

    def validate_solvency(
        self,
        audit: Audit,
        solvency_proof: SolvencyProofPB2,
        liabilities_commitment: EcPt,
        currency_to_asset_commitment: Mapping[Currency, EcPt],
    ) -> None:
        # Steps 14: Validate that the liabilities <= the assets
        # This function also performs steps 12 and 13
        if audit.version_number != solvency_proof.auditVersion:
            raise AuditProcessorFailedException("audit version mismatch")
        LOGGER.info("liabilities_commitment in base currency: %s", repr(liabilities_commitment))
        assets_commitment = self._convert_to_base_currency_commitment(
            audit, solvency_proof.assetCurrencyConversions, currency_to_asset_commitment
        )
        LOGGER.info("assets_commitment in base currency: %s", repr(assets_commitment))
        nizk = NIZK.deserialize(solvency_proof.nizk)
        verify_lte_commitment(liabilities_commitment, assets_commitment, nizk)

    def validate_block_timestamps(self, audit: AuditPB2) -> None:
        bitcoin_block = audit.bitcoinBlock
        ethereum_block = audit.ethereumBlock
        audit_timestamp = protobuf_to_datetime(audit.timestamp)

        bitcoin_block_metadata = self._blockchain_client.get_block_metadata_from_chain(Blockchain.BTC, bitcoin_block)
        ethereum_block_metadata = self._blockchain_client.get_block_metadata_from_chain(Blockchain.ETH, ethereum_block)

        bitcoin_block_timestamp = bitcoin_block_metadata.block_timestamp
        ethereum_block_timestamp = ethereum_block_metadata.block_timestamp
        if abs(bitcoin_block_timestamp - ethereum_block_timestamp) > BLOCKCHAIN_TIMESTAMP_EPSILON:
            raise AuditProcessorFailedException(
                "Time between BTC and ETH block" f"timestamps > acceptable epsilon ({BLOCKCHAIN_TIMESTAMP_EPSILON})"
            )
        if abs(bitcoin_block_timestamp - audit_timestamp) > BLOCKCHAIN_TIMESTAMP_EPSILON:
            raise AuditProcessorFailedException(
                "Time between BTC block and audit" "timestamp > acceptable epsilon ({BLOCKCHAIN_TIMESTAMP_EPSILON})"
            )
        if abs(ethereum_block_timestamp - audit_timestamp) > BLOCKCHAIN_TIMESTAMP_EPSILON:
            raise AuditProcessorFailedException(
                "Time between ETH block and audit" "timestamp > acceptable epsilon ({BLOCKCHAIN_TIMESTAMP_EPSILON})"
            )

    @record_auditor_latency
    def process_audit(self, audit_tarfile: str) -> None:  # type: ignore[misc]
        """
        `process_audit` should validate all information in the audit and store it in the database. database tables
        Please see Ravi's thesis for the audit verification procedure
        """
        LOGGER.info("Processing audit with tarfile %s", audit_tarfile)
        audit_cid_hex = os.path.basename(audit_tarfile).split(".")[0]
        audit_parent_folder = os.path.join(self._audit_folder, audit_cid_hex)
        self._safe_extract(audit_tarfile, audit_parent_folder)
        audit_data_location = os.path.join(audit_parent_folder, "audit")

        audit_metadata_pb = self._load_protobuf_from_file(AuditPB2, os.path.join(audit_data_location, "audit.bin"))
        self.validate_block_timestamps(audit_metadata_pb)
        LOGGER.info("Audit info: %s", repr(audit_metadata_pb))
        with self._sessionmaker() as session:
            audit = session.query(Audit).filter(Audit.version_number == audit_metadata_pb.auditVersion).one_or_none()
            if not audit:
                audit = self.add_audit_metadata(session, audit_metadata_pb)
                if not audit.bitcoin_block == audit_metadata_pb.bitcoinBlock:
                    raise AuditProcessorFailedException("Bitcoin block number mismatch")
                if not audit.ethereum_block == audit_metadata_pb.ethereumBlock:
                    raise AuditProcessorFailedException("Ethereum block number mismatch")
                self.add_new_user_keys(session, audit_data_location, audit)
                self.import_new_keys(session, audit_data_location, audit)
                self.import_new_accounts(session, audit_data_location, audit)
                self.import_new_deposit_key_accounts(session, audit_data_location, audit)
                session.commit()
            if audit.finished:
                LOGGER.info("Skipping audit %s as it is already finished", audit_tarfile)
                return
        bitcoin_block = audit_metadata_pb.bitcoinBlock
        ethereum_block = audit_metadata_pb.ethereumBlock

        self.process_new_blocks(bitcoin_block, ethereum_block)
        with self._sessionmaker() as session:
            audit = (
                session.query(Audit)
                .filter(Audit.version_number == audit_metadata_pb.auditVersion, Audit.finished.is_(False))
                .populate_existing()
                .with_for_update()
                .one()
            )
            self.process_account_delta_groups(session, audit_data_location, audit)
            session.flush()
            self.compute_deposit_liability_commitments(session, audit_data_location, audit)
            session.flush()
            cumulative_liability_commitment = self.compute_user_cumulative_liability_commitments(
                session, audit, audit_data_location
            )
            session.flush()
            LOGGER.info("cumulative_liability_commitment: %s", repr(cumulative_liability_commitment))
            currency_to_asset_commitment = self.compute_total_assets(session, audit_data_location, audit)
            session.flush()
            LOGGER.info("currency_to_asset_commitment: %s", repr(currency_to_asset_commitment))
            self.validate_exchange_rates(audit)
            solvency_proof = self._load_protobuf_from_file(
                SolvencyProofPB2, os.path.join(audit_data_location, "solvency_proof.bin")
            )
            self.validate_solvency(audit, solvency_proof, cumulative_liability_commitment, currency_to_asset_commitment)
            audit.finished = True
            LOGGER.info("Successfully processed audit: %s", repr(audit_metadata_pb))
            session.commit()
