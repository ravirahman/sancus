import logging
import secrets
import uuid
from decimal import Decimal
from typing import List, Optional, Sequence

import petlib.ec
import sqlalchemy.orm
from common.constants import ADMIN_UUID, SECP256K1_ORDER, Blockchain, Currency
from common.utils.uuid import generate_uuid4
from common.utils.zk import NIZK
from common.utils.zk.bit_commitment import generate_bit_commitment
from common.utils.zk.key_permutation import permute_private_key, permute_public_key
from protobufs.institution.account_pb2 import KeyType
from sqlalchemy import desc
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.blockchain_address_key import BlockchainAddressKey
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.sql.key_currency_account import KeyCurrencyAccount
from backend.sql.key_currency_block import KeyCurrencyBlock

LOGGER = logging.getLogger(__name__)


class KeyClient:
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        deposit_key_decoy_set_size: int,
    ) -> None:
        self._sessionmaker = sessionmaker
        self._deposit_key_decoy_set_size = deposit_key_decoy_set_size

    @staticmethod
    def _add_new_key_account_commitment(
        session: Session,
        key: Key,
        account_uuid: uuid.UUID,
        deposits_will_be_credited_to_account_for_key: bool,
    ) -> None:
        r = SECP256K1_ORDER.random()
        permuted_public_key = key.permuted_secp256k1_public_key
        _, bit_commitment_nizk = generate_bit_commitment(
            s=deposits_will_be_credited_to_account_for_key, G=permuted_public_key, r=r
        )
        session.add(
            KeyAccountCommitment(
                key_uuid=key.key_uuid,
                account_uuid=account_uuid,
                s=deposits_will_be_credited_to_account_for_key,
                r=r,
                nizk=bit_commitment_nizk,
            )
        )

    @staticmethod
    def _add_blockchain_addresses(session: Session, key: Key) -> None:
        for blockchain in Blockchain:
            address = key.get_address(blockchain)
            session.add(
                BlockchainAddressKey(
                    blockchain=blockchain,
                    address=address,
                    key_uuid=key.key_uuid,
                )
            )

    def _add_new_hot_key(self, session: Session, private_key: petlib.bn.Bn) -> Key:
        k = SECP256K1_ORDER.random()
        permuted_private_key, nizk = permute_private_key(private_key, k)
        key = Key(
            key_uuid=generate_uuid4(),
            key_type=KeyType.HOT,
            private_key=private_key,
            permuted_private_key=permuted_private_key,
            permutation_nizk=nizk,
        )
        session.add(key)
        self._track_owned_key(session, key)
        self._add_blockchain_addresses(session, key)
        return key

    @staticmethod
    def get_key_currency_block(
        session: Session, key_uuid: uuid.UUID, currency: Currency, block_number: int
    ) -> KeyCurrencyBlock:
        key_currency_block = (
            session.query(KeyCurrencyBlock)
            .filter(
                KeyCurrencyBlock.key_uuid == key_uuid,
                KeyCurrencyBlock.currency == currency,
                KeyCurrencyBlock.block_number <= block_number,
            )
            .order_by(desc(KeyCurrencyBlock.block_number))
            .first()
        )
        if key_currency_block is None:
            raise ValueError(f"key_uuid({key_uuid}) not found")
        return key_currency_block

    def get_balance(self, key_uuid: uuid.UUID, currency: Currency, block_number: int) -> Decimal:
        with self._sessionmaker() as session:
            key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == currency,
                )
                .one()
            )
            initial_balance = key_currency.initial_balance
            key_currency_block = self.get_key_currency_block(session, key_uuid, currency, block_number)
            balance = (
                initial_balance
                + key_currency_block.cumulative_tracked_deposit_amount
                - key_currency_block.cumulative_tracked_withdrawal_amount
            )
            assert isinstance(balance, Decimal)
            return balance

    def find_or_create_admin_key(
        self, session: Session, currency: Currency, *, excluded_key_uuids: Sequence[uuid.UUID] = tuple()
    ) -> Key:
        # this function returns a key, that for the session, is guaranteed to be admin
        # callee is required to perform an atomic update of the pending_admin_deposit counter
        # whenever using this key for deposits. When doing the atomic update, require that it is
        # still an admin key
        query = session.query(Key).filter(
            KeyCurrencyAccount.account_uuid == ADMIN_UUID,
            KeyCurrencyAccount.currency == currency,
            Key.key_uuid == KeyCurrencyAccount.key_uuid,
            Key.key_uuid.notin_(excluded_key_uuids),
        )
        count = query.count()
        key: Optional[Key] = None
        if count > 0:
            key = query.order_by(Key.created_at).offset(secrets.randbelow(count)).first()
        if key is None:
            private_key = SECP256K1_ORDER.random()
            key = self._add_new_hot_key(session, private_key)
        return key

    def make_new_hot_key(self) -> uuid.UUID:
        with self._sessionmaker() as session:
            private_key = SECP256K1_ORDER.random()
            key = self._add_new_hot_key(session, private_key)
            session.commit()
            key_uuid = key.key_uuid
            assert isinstance(key_uuid, uuid.UUID)
        return key_uuid

    def import_hot_key(self, private_key: petlib.bn.Bn, ethereum_transaction_count: int = 0) -> uuid.UUID:
        with self._sessionmaker() as session:
            key = self._add_new_hot_key(session, private_key)
            key.ethereum_transaction_count = ethereum_transaction_count
            session.commit()
            key_uuid = key.key_uuid
            assert isinstance(key_uuid, uuid.UUID)
        return key_uuid

    def _add_key_and_decoy_accounts(self, session: Session, key: Key, account: Account) -> None:
        decoy_account_uuids = [account.uuid]
        while len(decoy_account_uuids) < self._deposit_key_decoy_set_size:
            query = session.query(Account.uuid).filter(
                Account.uuid.notin_(decoy_account_uuids),
                Account.account_type == account.account_type,
                Account.currency == account.currency,
            )
            count = query.count()
            if count == 0:
                break
            decoy_accounts = query.order_by(Account.created_at).offset(secrets.randbelow(count)).first()
            if decoy_accounts is not None:
                (decoy_account_uuid,) = decoy_accounts
                decoy_account_uuids.append(decoy_account_uuid)
        # we want to randomize the order in which we add the accounts so timestamps aren't a giveaway
        while len(decoy_account_uuids) > 0:
            i = secrets.randbelow(len(decoy_account_uuids))
            account_uuid = decoy_account_uuids[i]
            decoy_account_uuids[i] = decoy_account_uuids[-1]
            decoy_account_uuids.pop()
            if account_uuid == account.uuid:
                self._add_new_key_account_commitment(
                    session,
                    key=key,
                    account_uuid=account.uuid,
                    # if account is owned by admin, never credit deposits
                    deposits_will_be_credited_to_account_for_key=account.user_uuid != ADMIN_UUID,
                )
                continue
            self._add_new_key_account_commitment(
                session,
                key=key,
                account_uuid=account_uuid,
                deposits_will_be_credited_to_account_for_key=False,
            )

    def find_or_create_key_and_assign_to_account(self, account_uuid: uuid.UUID) -> uuid.UUID:
        with self._sessionmaker() as session:
            account = (
                session.query(Account)
                .filter(
                    Account.uuid == account_uuid,
                )
                .one()
            )
            currency = account.currency
        bad_key_uuids: List[uuid.UUID] = []
        for _ in range(5):
            with self._sessionmaker() as session:
                # select a "candidate" without locking
                query = session.query(KeyCurrencyAccount.key_uuid).filter(
                    KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                    KeyCurrencyAccount.currency == currency,
                    KeyCurrencyAccount.pending_admin_deposits == 0,
                    KeyCurrencyAccount.key_uuid.notin_(bad_key_uuids),
                )
                count = query.count()
                if count == 0:
                    break
                offset = secrets.randbelow(count)
                key_uuids = query.order_by(KeyCurrencyAccount.created_at).offset(offset).first()
                if key_uuids is None:
                    break
                (key_uuid,) = key_uuids
                assert isinstance(key_uuid, uuid.UUID)
                # check to see if we are a decoy
                already_a_commitment = (
                    session.query(KeyAccountCommitment)
                    .filter(
                        KeyAccountCommitment.key_uuid == key_uuid, KeyAccountCommitment.account_uuid == account_uuid
                    )
                    .limit(1)
                    .count()
                    > 0
                )
                if already_a_commitment:
                    bad_key_uuids.append(key_uuid)
                    continue
            with self._sessionmaker() as session:
                # now, attempt to lock the candidate

                try:
                    key_currency_account = (
                        session.query(KeyCurrencyAccount)
                        .filter(
                            KeyCurrencyAccount.key_uuid == key_uuid,
                            KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                            KeyCurrencyAccount.currency == currency,
                            KeyCurrencyAccount.pending_admin_deposits == 0,
                        )
                        .populate_existing()
                        .with_for_update(nowait=True)
                        .one()
                    )
                except (OperationalError, NoResultFound):
                    # race condition
                    continue
                account = (
                    session.query(Account)
                    .filter(
                        Account.uuid == account_uuid,
                    )
                    .one()
                )
                key_currency_account.account_uuid = account_uuid
                # if you are admin, then setting pending_admin_deposits to 1
                # so this key is permanently locked
                key_currency_account.pending_admin_deposits = int(account_uuid == ADMIN_UUID)
                key = session.query(Key).filter(Key.key_uuid == key_currency_account.key_uuid).one()
                LOGGER.info("Assigning existing key(%s) to account(%s)", key.key_uuid, account.uuid)
                self._add_key_and_decoy_accounts(session, key, account)
                session.commit()
                return key_uuid
        # if we get here, none of the accounts we tried worked. Let's create a new one.
        with self._sessionmaker() as session:
            account = (
                session.query(Account)
                .filter(
                    Account.uuid == account_uuid,
                )
                .one()
            )
            private_key = SECP256K1_ORDER.random()
            key = self._add_new_hot_key(session, private_key)
            key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key.key_uuid,
                    KeyCurrencyAccount.currency == account.currency,
                    KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                    KeyCurrencyAccount.pending_admin_deposits == 0,
                )
                .populate_existing()
                .with_for_update()
                .one()
            )
            key_currency_account.account_uuid = account_uuid
            key_currency_account.pending_admin_deposits = int(account_uuid == ADMIN_UUID)
            LOGGER.info("Assigning new key(%s) to account(%s)", key.key_uuid, account.uuid)
            self._add_key_and_decoy_accounts(session, key, account)
            key_uuid = key.key_uuid
            assert isinstance(key_uuid, uuid.UUID)
            session.commit()
            return key_uuid

    def add_cold_key(
        self,
        key_uuid: uuid.UUID,
        public_key: petlib.ec.EcPt,
        permuted_private_key: petlib.bn.Bn,
        nizk: NIZK,
        ethereum_transaction_count: int = 0,
    ) -> None:
        key = Key(
            key_uuid=key_uuid,
            secp256k1_public_key=public_key,
            key_type=KeyType.COLD,
            permuted_private_key=permuted_private_key,
            permutation_nizk=nizk,
            ethereum_transaction_count=ethereum_transaction_count,
        )
        with self._sessionmaker() as session:
            session.add(key)
            self._add_blockchain_addresses(session, key)
            self._track_owned_key(session, key)
            session.commit()

    def add_anonymous_key(self, public_key: petlib.ec.EcPt) -> uuid.UUID:
        k = SECP256K1_ORDER.random()
        permuted_public_key, nizk = permute_public_key(public_key, k)
        key = Key(
            key_uuid=generate_uuid4(),
            secp256k1_public_key=public_key,
            key_type=KeyType.ANONYMOUS,
            permuted_secp256k1_public_key=permuted_public_key,
            permutation_nizk=nizk,
        )
        with self._sessionmaker() as session:
            session.add(key)
            self._add_blockchain_addresses(session, key)
            self._track_anonymous_key(session, key)
            session.commit()
            key_uuid = key.key_uuid
            assert isinstance(key_uuid, uuid.UUID)
        return key_uuid

    @staticmethod
    def _track_owned_key(session: Session, key: Key) -> None:
        for currency in Currency:
            key_currency_account = KeyCurrencyAccount(
                key_uuid=key.key_uuid,
                currency=currency,
                account_uuid=ADMIN_UUID,
                available_balance=None,
            )
            session.add(key_currency_account)

    @staticmethod
    def _track_anonymous_key(session: Session, key: Key) -> None:
        for currency in Currency:
            key_currency_account = KeyCurrencyAccount(
                key_uuid=key.key_uuid,
                currency=currency,
            )
            session.add(key_currency_account)

    def assign_key_as_decoy_to_account(self, *, key_uuid: uuid.UUID, account_uuid: uuid.UUID) -> None:
        assert account_uuid != ADMIN_UUID, "cannot assign decoy for admin"
        with self._sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            self._add_new_key_account_commitment(
                session,
                key,
                account_uuid,
                deposits_will_be_credited_to_account_for_key=False,
            )
            session.commit()

    def assign_key_for_deposits_to_account(self, *, key_uuid: uuid.UUID, account_uuid: uuid.UUID) -> None:
        assert account_uuid != ADMIN_UUID, "cannot assign back to admin"
        with self._sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            if not key.ownership_s:
                raise ValueError(
                    "key is not owned and therefore "
                    "cannot be assigned since we do not know the corresponding private key"
                )
            account = session.query(Account).filter(Account.uuid == account_uuid).one()
            key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == account.currency,
                    KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                    KeyCurrencyAccount.pending_admin_deposits == 0,
                )
                .populate_existing()
                .with_for_update()
                .one()
            )
            key_currency_account.account_uuid = account_uuid
            self._add_new_key_account_commitment(
                session,
                key=key,
                account_uuid=account_uuid,
                deposits_will_be_credited_to_account_for_key=True,
            )
            session.commit()
