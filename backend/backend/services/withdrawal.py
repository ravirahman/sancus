import logging
import secrets
import uuid
from decimal import Decimal
from typing import List, Optional, Sequence, cast

import grpc
import petlib
import sqlalchemy.orm
from common.constants import (
    CURRENCY_PRECISIONS,
    CURRENCY_TO_BLOCKCHAIN,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
    Currency,
)
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid, generate_uuid4
from google.protobuf.any_pb2 import Any
from protobufs.account_pb2 import (
    AccountDeltaGroupChallengeRequest,
    AccountType,
    PublicAccountDeltaCommitment,
    RevealedAccountDeltaCommitment,
    RevealedPedersenCommitment,
    UnsignedBlockchainTransacton,
)
from protobufs.institution.account_pb2 import (
    KeyType,
    TransactionStatus,
    TransactionType,
    WithdrawalTransaction,
)
from protobufs.institution.withdrawal_pb2 import (
    InitiateWithdrawalRequest,
    InitiateWithdrawalResponse,
    ProcessWithdrawalRequest,
    ProcessWithdrawalResponse,
)
from protobufs.institution.withdrawal_pb2_grpc import (
    WithdrawalServicer,
    add_WithdrawalServicer_to_server,
)
from protobufs.webauthn_pb2 import ChallengeRequest
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.account_delta import AccountDelta
from backend.sql.account_delta_group import AccountDeltaGroup
from backend.sql.account_delta_group_blockchain_transaction import (
    AccountDeltaGroupBlockchainTransaction,
)
from backend.sql.blockchain_transaction import BlockchainTransaction
from backend.sql.challenge import Challenge
from backend.sql.transaction import Transaction
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.blockchain_client.vendor_base import FundsUnavailableException
from backend.utils.jwt_client import AuthenticatedServicer, JWTClient, authenticated
from backend.utils.key_client import KeyClient
from backend.utils.webauthn_client import WebauthnClient

LOGGER = logging.getLogger(__name__)


class WithdrawalService(WithdrawalServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        webauthn_client: WebauthnClient,
        account_anonymity_set_size: int,
        blockchain_client: BlockchainClient,
        key_client: KeyClient,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._account_anonymity_set_size = account_anonymity_set_size
        self._webauthn_client = webauthn_client
        self._jwt_client = jwt_client
        self._blockchain_client = blockchain_client
        self._key_client = key_client
        add_WithdrawalServicer_to_server(self, server)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    def _create_withdrawals(
        self,
        session: Session,
        account_delta_group_uuid: uuid.UUID,
        currency: Currency,
        amount: Decimal,
        destintation_address: str,
        anonymity_set_currencies: Sequence[Currency],
    ) -> Sequence[UnsignedBlockchainTransacton]:
        unsigned_blockchain_transactions: List[UnsignedBlockchainTransacton] = []
        existing_dest_keys: List[uuid.UUID] = []
        for anonymous_currency in anonymity_set_currencies:
            dest_key = self._key_client.find_or_create_admin_key(
                session, anonymous_currency, excluded_key_uuids=existing_dest_keys
            )  # TODO(Anne) -- pick a good destination address
            existing_dest_keys.append(dest_key.key_uuid)
            tx_id, tx_params = self._blockchain_client.create_pending_transaction(
                session,
                Decimal("0.01"),  # TODO(Anne) -- pick a smart random amount
                anonymous_currency,
                dest_key.get_address(CURRENCY_TO_BLOCKCHAIN[anonymous_currency]),
                KeyType.HOT,
                should_dest_be_admin=True,
            )
            unsigned_blockchain_transactions.append(
                UnsignedBlockchainTransacton(
                    blockchain=CURRENCY_TO_BLOCKCHAIN[anonymous_currency].name,
                    txParams=tx_params,
                )
            )
            session.add(
                AccountDeltaGroupBlockchainTransaction(
                    account_delta_group_uuid=account_delta_group_uuid,
                    blockchain=CURRENCY_TO_BLOCKCHAIN[anonymous_currency],
                    blockchain_withdrawal_uuid=tx_id,
                )
            )
        tx_id, tx_params = self._blockchain_client.create_pending_transaction(
            session,
            amount,
            currency,
            destintation_address,
            KeyType.HOT,
            should_dest_be_admin=False,
        )
        unsigned_blockchain_transactions.append(
            UnsignedBlockchainTransacton(
                blockchain=CURRENCY_TO_BLOCKCHAIN[currency].name,
                txParams=tx_params,
            )
        )
        session.add(
            AccountDeltaGroupBlockchainTransaction(
                account_delta_group_uuid=account_delta_group_uuid,
                blockchain=CURRENCY_TO_BLOCKCHAIN[currency],
                blockchain_withdrawal_uuid=tx_id,
            )
        )
        return unsigned_blockchain_transactions

    @authenticated
    def InitiateWithdrawal(
        self,
        request: InitiateWithdrawalRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> InitiateWithdrawalResponse:
        from_account_uuid = bytes_to_uuid(request.fromAccountId)
        withdrawal_amount = Decimal(request.amount)
        destination_address = request.destinationAddress

        account_delta_group_uuid = generate_uuid4()
        revealed_account_commitments: List[RevealedAccountDeltaCommitment] = []
        public_account_commitments: List[PublicAccountDeltaCommitment] = []
        with self._sessionmaker() as session:
            try:
                from_account = (
                    session.query(Account)
                    .filter(
                        Account.user_uuid == user_uuid,
                        Account.uuid == from_account_uuid,
                    )
                    .one()
                )
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "From account not found for user")
                raise ValueError("From account not found for user") from e
            if from_account.account_type != AccountType.DEPOSIT_ACCOUNT:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "From account type must be a deposit account")
                raise ValueError("From account type must be a deposit account")

            decoy_accounts: List[Account] = []
            while len(decoy_accounts) < self._account_anonymity_set_size:
                query = session.query(Account).filter(
                    Account.user_uuid == user_uuid,
                    Account.uuid.notin_([from_account_uuid, *[account.uuid for account in decoy_accounts]]),
                )
                count = query.count()
                if count == 0:
                    break
                account = query.order_by(Account.created_at).offset(secrets.randbelow(count)).first()
                if account is not None:
                    decoy_accounts.append(account)

            anonymity_set_currencies: List[Currency] = []
            for account in (from_account, *decoy_accounts):
                random_val = SECP256K1_ORDER.random()
                amount = petlib.bn.Bn(0)
                currency = cast(Currency, account.currency)
                anonymity_set_currencies.append(currency)
                account_uuid = account.uuid
                if account_uuid == from_account_uuid:
                    amount = -petlib.bn.Bn.from_decimal(str(int(withdrawal_amount * CURRENCY_PRECISIONS[currency])))
                commitment = amount * SECP256K1_GENERATOR + random_val * SECP256K1_ALTERNATIVE_GENERATOR
                account_delta = AccountDelta(
                    account_delta_group_uuid=account_delta_group_uuid,
                    account_uuid=account_uuid,
                    amount=amount,
                    random_val=random_val,
                )
                session.add(account_delta)
                public_account_commitments.append(
                    PublicAccountDeltaCommitment(accountId=account_uuid.bytes, commitment=commitment.export())
                )
                revealed_account_commitments.append(
                    RevealedAccountDeltaCommitment(
                        accountId=account_uuid.bytes,
                        commitment=RevealedPedersenCommitment(
                            r=str(random_val),
                            x=str(amount),
                        ),
                    )
                )
            from_currency = cast(Currency, from_account.currency)
            try:
                transactions = self._create_withdrawals(
                    session,
                    account_delta_group_uuid,
                    from_currency,
                    withdrawal_amount,
                    destination_address,
                    anonymity_set_currencies,
                )
            except FundsUnavailableException as e:
                LOGGER.info("Unable to create the transactions", exc_info=True)
                context.abort(grpc.StatusCode.ABORTED, "Failed to create withdrawal. Try again after a delay.")
                raise e

            withdrawal_challenge_request = AccountDeltaGroupChallengeRequest(
                commitments=public_account_commitments,
                transactions=transactions,
            )
            challenge_request, webauthn_challenge_request = self._webauthn_client.build_assertion_request(
                session,
                user_uuid=user_uuid,
                challenge_type=ChallengeRequest.ChallengeType.WITHDRAWAL,
                request=withdrawal_challenge_request,
            )
            any_request_pb = Any()
            any_request_pb.Pack(request)
            session.add(
                AccountDeltaGroup(
                    uuid=account_delta_group_uuid,
                    user_uuid=user_uuid,
                    status=TransactionStatus.PENDING,
                    challenge_uuid=bytes_to_uuid(challenge_request.nonce),
                )
            )
            session.commit()
            LOGGER.debug(
                "Stored initiate withdrawal for user %s, id %s",
                user_uuid,
                account_delta_group_uuid,
            )
        return InitiateWithdrawalResponse(
            id=account_delta_group_uuid.bytes,
            challengeRequest=challenge_request,
            revealedCommitments=revealed_account_commitments,
            credentialRequest=webauthn_challenge_request,
        )

    @authenticated
    def ProcessWithdrawal(
        self,
        request: ProcessWithdrawalRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> ProcessWithdrawalResponse:
        account_delta_group_uuid = bytes_to_uuid(request.id)
        with self._sessionmaker() as session:
            LOGGER.debug("Processing withdrawal for user %s, id %s", user_uuid, account_delta_group_uuid)
            account_delta_group = (
                session.query(AccountDeltaGroup)
                .filter(
                    AccountDeltaGroup.user_uuid == user_uuid,
                    AccountDeltaGroup.uuid == account_delta_group_uuid,
                )
                .one()
            )
            challenge_uuid = account_delta_group.challenge_uuid
            assert isinstance(challenge_uuid, uuid.UUID)
            webauthn_user_uuid = self._webauthn_client.validate_assertion_response(
                session,
                challenge_id=challenge_uuid,
                challenge_type=ChallengeRequest.ChallengeType.WITHDRAWAL,
                response=request.assertion,
            )
            if webauthn_user_uuid != user_uuid:
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "response signed by wrong user uuid")
                raise ValueError("invalid user signature")

            account_deltas = (
                session.query(AccountDelta)
                .filter(AccountDelta.account_delta_group_uuid == account_delta_group_uuid)
                .all()
            )

            from_account_delta: Optional[AccountDelta] = None
            challenge = session.query(Challenge).filter(Challenge.uuid == challenge_uuid).one()
            challenge_request = challenge.challenge_request

            for account_delta in account_deltas:
                amount = account_delta.amount
                assert amount is not None

                if amount < 0:
                    from_account_delta = account_delta
                    break

            assert from_account_delta is not None
            timestamp = get_current_datetime()

            account = (
                session.query(Account)
                .filter(Account.uuid == from_account_delta.account_uuid)
                .populate_existing()
                .with_for_update()
                .one()
            )
            amount_bn = from_account_delta.amount
            assert amount_bn is not None
            currency = cast(Currency, account.currency)
            amount = Decimal(int(amount_bn)) / CURRENCY_PRECISIONS[currency]
            if account.available_amount + amount < 0:
                context.abort(grpc.StatusCode.UNAVAILABLE, "From account not sufficiently high")
                raise ValueError("From account not sufficiently high")
            withdrawal_transaction = WithdrawalTransaction(
                accountDeltasRequestId=account_delta_group_uuid.bytes,
                challengeRequest=challenge_request,
                assertion=challenge.authenticator_assertion_response,
            )
            any_pb = Any()
            any_pb.Pack(withdrawal_transaction)
            transaction = Transaction(
                uuid=generate_uuid4(),
                account_uuid=account.uuid,
                transaction_type=TransactionType.WITHDRAWAL,
                timestamp=timestamp,
                status=TransactionStatus.COMPLETED,
                amount=amount,
                extra=any_pb,
            )
            session.add(transaction)

            row_count = (
                session.query(AccountDeltaGroup)
                .filter(
                    AccountDeltaGroup.user_uuid == user_uuid,
                    AccountDeltaGroup.uuid == account_delta_group_uuid,
                    AccountDeltaGroup.status == TransactionStatus.PENDING,
                )
                .update({AccountDeltaGroup.status: TransactionStatus.COMPLETED})
            )
            if row_count != 1:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "bad request.id")
                raise ValueError("bad request.id")

            adgbts = (
                session.query(AccountDeltaGroupBlockchainTransaction)
                .filter(
                    AccountDeltaGroupBlockchainTransaction.account_delta_group_uuid == account_delta_group_uuid,
                )
                .all()
            )
            for adgbt in adgbts:
                blockchain_identifier = self._blockchain_client.queue_hot_transaction(
                    session,
                    adgbt.blockchain,
                    adgbt.blockchain_withdrawal_uuid,
                )
                # it's ok this races since it will always be the same value
                adgbt.blockchain_transaction_identifier = blockchain_identifier
                session.add(
                    BlockchainTransaction(
                        blockchain=CURRENCY_TO_BLOCKCHAIN[currency],
                        blockchain_transaction_identifier=blockchain_identifier,
                        transaction_uuid=transaction.uuid,
                    )
                )
            account.available_amount += amount
            account.pending_amount += amount
            session.commit()

        return ProcessWithdrawalResponse()
