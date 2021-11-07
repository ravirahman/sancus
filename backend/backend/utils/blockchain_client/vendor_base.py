import hashlib
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, List, Mapping, NamedTuple, Sequence, Tuple

import sqlalchemy.orm
from common.constants import CURRENCY_TO_BLOCKCHAIN, Blockchain, Currency
from common.utils.datetime import get_current_datetime
from common.utils.managed_thread_pool import ManagedThreadPool
from common.utils.uuid import generate_uuid4
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from protobufs.institution.account_pb2 import TransactionStatus, TransactionType
from sqlalchemy import tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.sql.account import Account
from backend.sql.block import Block
from backend.sql.blockchain_address_key import BlockchainAddressKey
from backend.sql.blockchain_transaction import BlockchainTransaction
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.sql.key_currency_account import KeyCurrencyAccount
from backend.sql.key_currency_block import KeyCurrencyBlock
from backend.sql.transaction import Transaction
from backend.utils.key_client import KeyClient

if TYPE_CHECKING:
    from protobufs.institution.account_pb2 import (  # pylint: disable=ungrouped-imports
        KeyType,
    )

LOGGER = logging.getLogger(__name__)


class FundsUnavailableException(Exception):
    # should be raised by create_pending_transaction() if the
    # institution does not have available funds to make the requested
    # withdrawal
    pass


class BlockMetadata(NamedTuple):
    block_number: int
    block_hash: HexBytes
    parent_block_hash: HexBytes
    block_timestamp: datetime


class VendorBaseBlockchainClient(ABC):
    blockchain: Blockchain

    def __init__(self, max_workers: int, config_start_block_number: int) -> None:
        self._pool = ManagedThreadPool(max_workers=max_workers)
        # process the start block
        with self.sessionmaker() as session:
            start_block = (
                session.query(Block)
                .filter(
                    Block.blockchain == self.blockchain,
                )
                .order_by(Block.block_number)
                .first()
            )
            if start_block is None:
                self.start_block_number = config_start_block_number
                return
            if start_block.block_number != config_start_block_number:
                raise ValueError(
                    f"config.start_block({config_start_block_number}) != db start_block({start_block.block_number})"
                )
            self.start_block_number = start_block.block_number

    @property
    @abstractmethod
    def sessionmaker(self) -> sqlalchemy.orm.sessionmaker:
        raise NotImplementedError()

    @property
    @abstractmethod
    def rebroadcast_interval(self) -> timedelta:
        raise NotImplementedError()

    @property
    @abstractmethod
    def num_confirmations(self) -> int:
        raise NotImplementedError()

    @property
    @abstractmethod
    def key_client(self) -> KeyClient:
        raise NotImplementedError()

    @staticmethod
    def _create_transaction_identifier(data: Mapping[bytes, bytes]) -> HexBytes:
        data_list = list(data.items())
        data_list.sort(key=lambda x: x[0])  # sort by the keys, alphabetically
        m_digest = hashlib.sha256()
        for k, v in data_list:
            m_digest.update(k)
            m_digest.update(b"=")
            m_digest.update(v)
            m_digest.update(b",")
        return HexBytes(m_digest.digest())

    def _create_withdrawal_transaction_identifier(self, txn_hash: HexBytes) -> HexBytes:
        return self._create_transaction_identifier({b"TYPE": b"WITHDRAWAL", b"TRANSACTION_HASH": txn_hash})

    @property
    def _blockchain_currencies(self) -> Sequence[Currency]:
        blockchain_currencies: List[Currency] = []
        for currency, blockchain in CURRENCY_TO_BLOCKCHAIN.items():
            if blockchain == self.blockchain:
                blockchain_currencies.append(currency)
        return blockchain_currencies

    def validate_block_processed(self, block_number: int) -> None:
        with self.sessionmaker() as session:
            session.query(Block).filter(
                Block.blockchain == self.blockchain,
                Block.block_number == block_number,
                Block.processed.is_(True),
            ).one()  # raises exceptions on failure

    def _update_blockchain_transaction_block_numbers(
        self, block_number: int, transaction_identifiers: Sequence[HexBytes]
    ) -> None:
        LOGGER.info(
            "Updating blockchain transaction block numbers to %d for transactions %s",
            block_number,
            transaction_identifiers,
        )
        with self.sessionmaker() as session:
            session.query(BlockchainTransaction).filter(
                BlockchainTransaction.blockchain == self.blockchain,
                BlockchainTransaction.blockchain_transaction_identifier.in_(transaction_identifiers),
            ).update(
                {
                    BlockchainTransaction.block_number: block_number,
                },
                synchronize_session=False,
            )
            session.commit()

    def _create_deposit_transaction(
        self,
        block_number: int,
        timestamp: datetime,
        blockchain_transaction_identifier: HexBytes,
        account_uuid: uuid.UUID,
        amount: Decimal,
    ) -> None:
        # if we already have the blockchain transaction, then
        # we also have the transaction
        # determine if the blockchain transaction was already stored
        with self.sessionmaker() as session:
            blockchain_transaction = (
                session.query(BlockchainTransaction)
                .filter(
                    BlockchainTransaction.blockchain == self.blockchain,
                    BlockchainTransaction.blockchain_transaction_identifier == blockchain_transaction_identifier,
                )
                .one_or_none()
            )
            if blockchain_transaction is not None:
                return
            blockchain_transaction = BlockchainTransaction(
                blockchain=self.blockchain,
                blockchain_transaction_identifier=blockchain_transaction_identifier,
                block_number=block_number,
                transaction_uuid=generate_uuid4(),
            )
            session.add(blockchain_transaction)
            session.merge(
                Transaction(
                    uuid=blockchain_transaction.transaction_uuid,
                    account_uuid=account_uuid,
                    transaction_type=TransactionType.DEPOSIT,
                    timestamp=timestamp,
                    status=TransactionStatus.PENDING,
                    amount=amount,
                )
            )
            account = (
                session.query(Account).filter(Account.uuid == account_uuid).populate_existing().with_for_update().one()
            )
            account.pending_amount += amount
            session.commit()

    def _update_key_currency_block(
        self,
        currency: Currency,
        key_uuid_to_withdrawal_amount: Mapping[uuid.UUID, Decimal],
        key_uuid_to_deposit_amount: Mapping[uuid.UUID, Decimal],
        block_number: int,
    ) -> None:
        # This function should ONLY be called if block_number - 1 has already been processed.
        # It does NOT validate this precondition
        with self.sessionmaker() as session:
            key_currency_accounts = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.currency == currency,
                    KeyCurrencyAccount.key_uuid.in_(
                        [*key_uuid_to_withdrawal_amount.keys(), *key_uuid_to_deposit_amount.keys()]
                    ),
                    # doing less than instead of lte since, on the initial_balance_block_number, we
                    # already set the available balance
                    KeyCurrencyAccount.initial_balance_block_number < block_number,
                )
                .all()
            )
            key_uuids = [kca.key_uuid for kca in key_currency_accounts]

        for key_uuid in key_uuids:
            deposit_amount = key_uuid_to_deposit_amount.get(key_uuid, Decimal(0))
            withdrawal_amount = key_uuid_to_withdrawal_amount.get(key_uuid, Decimal(0))
            with self.sessionmaker() as session:
                does_key_currency_block_exist = (
                    session.query(KeyCurrencyBlock)
                    .filter(
                        KeyCurrencyBlock.key_uuid == key_uuid,
                        KeyCurrencyBlock.block_number == block_number,
                        KeyCurrencyBlock.currency == currency,
                    )
                    .limit(1)
                    .count()
                    > 0
                )
                if not does_key_currency_block_exist:
                    prev_key_currency_block = self.key_client.get_key_currency_block(
                        session,
                        key_uuid,
                        currency,
                        block_number - 1,
                    )
                    cum_tracked_withdrawals = (
                        prev_key_currency_block.cumulative_tracked_withdrawal_amount + withdrawal_amount
                    )
                    cum_tracked_deposits = prev_key_currency_block.cumulative_tracked_deposit_amount + deposit_amount
                    session.add(
                        KeyCurrencyBlock(
                            key_uuid=key_uuid,
                            block_number=block_number,
                            currency=currency,
                            deposit_amount=deposit_amount,
                            withdrawal_amount=withdrawal_amount,
                            cumulative_tracked_withdrawal_amount=cum_tracked_withdrawals,
                            cumulative_tracked_deposit_amount=cum_tracked_deposits,
                        )
                    )
                    key_currency = (
                        session.query(KeyCurrencyAccount)
                        .filter(
                            KeyCurrencyAccount.key_uuid == key_uuid,
                            KeyCurrencyAccount.currency == currency,
                        )
                        .populate_existing()
                        .with_for_update()
                        .one()
                    )
                    if key_currency.account_uuid is not None:  # is not Anonymous
                        key_currency.available_balance += deposit_amount
                    session.commit()

    def _update_pending_balance(self, now_confirmed_block_number: int) -> None:
        # all these transactions are now considered confirmed.
        # Select all pending transactons in this block, and make them confirmed
        with self.sessionmaker() as session:
            blockchain_transactons = (
                session.query(BlockchainTransaction)
                .filter(
                    BlockchainTransaction.block_number == now_confirmed_block_number,
                )
                .all()
            )
        for blockchain_transaction in blockchain_transactons:
            # TODO run in a thread pool executor
            with self.sessionmaker() as session:
                transaction, account = (
                    session.query(Transaction, Account)
                    .filter(
                        Transaction.uuid == blockchain_transaction.transaction_uuid,
                        Account.uuid == Transaction.account_uuid,
                    )
                    .populate_existing()
                    .with_for_update()
                    .one()
                )
                if transaction.status != TransactionStatus.PENDING:
                    # the transaction was already processed and the balance is already reflected in the available
                    # balance
                    continue
                transaction.status = TransactionStatus.COMPLETED
                new_available_amount = account.available_amount
                is_deposit = transaction.amount > 0
                if is_deposit:
                    # not adjusting available amount for withdrawals since it was already deducted
                    new_available_amount += transaction.amount
                account.pending_amount -= transaction.amount
                account.available_amount = new_available_amount
                session.commit()

    @abstractmethod
    def get_latest_block_number_from_chain(self) -> int:
        raise NotImplementedError()

    @abstractmethod
    def get_block_metadata_from_chain(self, block_number: int) -> BlockMetadata:
        raise NotImplementedError()

    @abstractmethod
    def get_public_key(self, transaction_id: str) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def create_pending_transaction(
        self,
        session: Session,
        amount: Decimal,
        currency: Currency,
        destination_address: str,
        key_type: "KeyType.V",
        should_dest_be_admin: bool,
    ) -> Tuple[uuid.UUID, Any]:
        # construct a transaction `amount` of `currency` going to `destination_address`
        # returns a tuple of the transaction id and the transaction data
        raise NotImplementedError()

    @abstractmethod
    def _create_transactions_and_update_balances(
        self,
        block_metadata: BlockMetadata,
    ) -> Sequence[HexBytes]:
        raise NotImplementedError()

    def get_cumulative_deposits(
        self, key_uuid: uuid.UUID, currency: Currency, from_block_number: int, to_block_number: int
    ) -> Decimal:
        # Gets the cumulative deposits on [from_block_number; to_block_number], inclusive
        if from_block_number <= self.start_block_number:
            raise ValueError(f"from_block_number({from_block_number}) <= start_block({self.start_block_number})")
        self.validate_block_processed(to_block_number)
        with self.sessionmaker() as session:
            # going back a block since the sum is inclusive
            # should always be at least one after the initial_balance_block_number since we weren't tracking
            # the key on that block; we started tracking the key on the next block
            from_key_currency_block = self.key_client.get_key_currency_block(
                session, key_uuid, currency, from_block_number - 1
            )
            to_key_currency_block = self.key_client.get_key_currency_block(session, key_uuid, currency, to_block_number)
            cumulative_tracked_deposit_amount = (
                to_key_currency_block.cumulative_tracked_deposit_amount
                - from_key_currency_block.cumulative_tracked_deposit_amount
            )
            assert isinstance(cumulative_tracked_deposit_amount, Decimal)
            return cumulative_tracked_deposit_amount

    @abstractmethod
    def queue_cold_transaction(
        self, session: Session, transaction_id: uuid.UUID, signed_transaction: HexBytes
    ) -> HexBytes:
        raise NotImplementedError()

    @abstractmethod
    def queue_hot_transaction(self, session: Session, transaction_id: uuid.UUID) -> HexBytes:
        raise NotImplementedError()

    @abstractmethod
    def get_cold_transactions_awaiting_signature(self) -> Sequence[Any]:
        raise NotImplementedError()

    @abstractmethod
    def _broadcast_transaction(self, signed_tx: HexBytes) -> HexBytes:
        raise NotImplementedError()

    def _broadcast_new_transactions(self) -> None:
        with self.sessionmaker() as session:
            pending_transactions = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.signed_tx.isnot(None),
                    BlockchainWithdrawal.last_broadcast_at.is_(None),
                    BlockchainWithdrawal.blockchain == self.blockchain,
                )
                .all()
            )
        for pending_transaction in pending_transactions:
            signed_tx = pending_transaction.signed_tx
            txn_hash = self._broadcast_transaction(signed_tx)
            with self.sessionmaker() as session:
                row_count = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        BlockchainWithdrawal.uuid == pending_transaction.uuid,
                    )
                    .update(
                        {
                            BlockchainWithdrawal.txn_hash: txn_hash,
                            BlockchainWithdrawal.last_broadcast_at: get_current_datetime(),
                        }
                    )
                )
                assert row_count == 1
                session.commit()

    def _rebroadcast_transactions(self) -> None:
        with self.sessionmaker() as session:
            pending_transactions = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.last_broadcast_at <= get_current_datetime() - self.rebroadcast_interval,
                    BlockchainWithdrawal.blockchain == self.blockchain,
                )
                .all()
            )
        for pending_transaction in pending_transactions:
            signed_tx = pending_transaction.signed_tx
            assert signed_tx is not None
            txn_hash = self._broadcast_transaction(signed_tx)
            assert txn_hash == pending_transaction.txn_hash
            with self.sessionmaker() as session:
                row_count = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        BlockchainWithdrawal.uuid == pending_transaction.uuid,
                    )
                    .update(
                        {
                            BlockchainWithdrawal.last_broadcast_at: get_current_datetime(),
                        }
                    )
                )
                assert row_count == 1
                session.commit()

    def _update_key_currency_commitments(self, block_metadata: BlockMetadata) -> None:
        with self.sessionmaker() as session:
            records = (
                session.query(KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.block_number.is_(None),
                    KeyAccountCommitment.account_uuid == Account.uuid,
                    KeyCurrencyAccount.currency == Account.currency,
                    KeyCurrencyAccount.currency.in_(self._blockchain_currencies),
                    KeyCurrencyAccount.key_uuid == KeyAccountCommitment.key_uuid,
                    KeyCurrencyAccount.initial_balance_block_number <= block_metadata.block_number,
                )
                .all()
            )
            if __debug__:
                for record in records:
                    LOGGER.debug(
                        "setting block number to %d in KeyAccountCommitment key(%s), account(%s) ",
                        block_metadata.block_number,
                        record.key_uuid,
                        record.account_uuid,
                    )

            key_and_account_uuids: List[Tuple[uuid.UUID, uuid.UUID]] = [
                (kac.key_uuid, kac.account_uuid) for kac in records
            ]
            row_count = (
                session.query(KeyAccountCommitment)
                .filter(
                    tuple_(KeyAccountCommitment.key_uuid, KeyAccountCommitment.account_uuid).in_(key_and_account_uuids),
                    KeyAccountCommitment.block_number.is_(None),
                )
                .update(
                    {
                        KeyAccountCommitment.block_number: block_metadata.block_number,
                    }
                )
            )
            if row_count != len(records):
                raise RuntimeError("failed to update the block_number on all key account commitments")
            session.commit()

    @abstractmethod
    def _get_balance_from_chain(
        self, session: Session, address: str, currency: Currency, block_metadata: BlockMetadata
    ) -> Decimal:
        raise NotImplementedError()

    def _track_key_currency_block(
        self,
        *,
        key_uuid: uuid.UUID,
        block_metadata: BlockMetadata,
        address: str,
        currency: Currency,
        is_anonymous: bool,
    ) -> None:
        with self.sessionmaker() as session:
            # add a KeyCurrencyBlock for the previous block that has a bunch of zeros
            initial_key_currency_block = KeyCurrencyBlock(
                key_uuid=key_uuid,
                block_number=block_metadata.block_number,
                currency=currency,
                cumulative_tracked_withdrawal_amount=Decimal(0),
                cumulative_tracked_deposit_amount=Decimal(0),
            )
            session.add(initial_key_currency_block)
            bal = self._get_balance_from_chain(session, address, currency, block_metadata)
            available_balance = None if is_anonymous else bal
            key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == currency,
                    KeyCurrencyAccount.available_balance.is_(None),
                    KeyCurrencyAccount.initial_balance_block_number.is_(None),
                    KeyCurrencyAccount.initial_balance.is_(None),
                )
                .populate_existing()
                .with_for_update()
                .one()
            )
            key_currency_account.available_balance = available_balance
            key_currency_account.initial_balance_block_number = block_metadata.block_number
            key_currency_account.initial_balance = bal
            LOGGER.debug(
                "adding initial_key_currency_block for key(%s), currency(%s), block(%d)",
                key_uuid,
                currency,
                block_metadata.block_number,
            )
            session.commit()

    def _track_new_key_currencies(self, block_metadata: BlockMetadata) -> None:
        with self.sessionmaker() as session:
            results = (
                session.query(
                    Key.key_uuid,
                    BlockchainAddressKey.address,
                    KeyCurrencyAccount.currency,
                    KeyCurrencyAccount.account_uuid,
                )
                .filter(
                    KeyCurrencyAccount.currency.in_(self._blockchain_currencies),
                    KeyCurrencyAccount.initial_balance_block_number.is_(None),
                    BlockchainAddressKey.blockchain == self.blockchain,
                    BlockchainAddressKey.key_uuid == KeyCurrencyAccount.key_uuid,
                    Key.key_uuid == KeyCurrencyAccount.key_uuid,
                )
                .all()
            )
        with self._pool:
            for key_uuid, address, currency, account_uuid in results:
                is_anonymous = account_uuid is None

                def bound_track_key_currency_block(
                    key_uuid: uuid.UUID = key_uuid,
                    address: str = address,
                    currency: Currency = currency,
                    is_anonymous: bool = is_anonymous,
                ) -> None:
                    self._track_key_currency_block(
                        key_uuid=key_uuid,
                        block_metadata=block_metadata,
                        address=address,
                        currency=currency,
                        is_anonymous=is_anonymous,
                    )

                self._pool(bound_track_key_currency_block)

    def process_block(self, block_number: int) -> None:
        block_metadata = self.get_block_metadata_from_chain(block_number)
        block_number = block_metadata.block_number
        block_timestamp = block_metadata.block_timestamp
        if block_number < self.start_block_number:
            raise ValueError("Block number is before start block number")
        with self.sessionmaker() as session:
            if block_number > self.start_block_number:
                previous_block = (
                    session.query(Block)
                    .filter(
                        Block.blockchain == self.blockchain,
                        Block.block_number == block_number - 1,
                        Block.processed.is_(True),
                    )
                    .one()
                )
                if previous_block.block_hash != block_metadata.parent_block_hash:
                    raise ValueError(
                        "Blockchain forked -- the current block's "
                        f"parentHash({block_metadata.parent_block_hash.hex()}) "
                        "differs from the previous processed block's "
                        f"blockHash({block_metadata.block_hash.hex()})"
                    )
            try:
                block = Block(
                    blockchain=self.blockchain,
                    block_number=block_number,
                    block_hash=block_metadata.block_hash,
                    timestamp=block_timestamp,
                )
                session.add(block)
                session.commit()
            except IntegrityError as e:
                session.rollback()
                # either we already processed this block, or there is a new block block with the same ID
                block = (
                    session.query(Block)
                    .filter(
                        Block.blockchain == self.blockchain,
                        Block.block_number == block_number,
                    )
                    .one()
                )
                if block.block_hash != block_metadata.block_hash:
                    raise RuntimeError(
                        "Blockchain diverged! Block with same ID processed with different block hash"
                    ) from e
        # scan KeyCurrencyAccount for accounts with an ID that do not have a tracking start block
        LOGGER.info(
            "Callling create_transactions and update balances for blockchain %s, block number %d",
            self.blockchain,
            block_metadata.block_number,
        )
        transaction_identifiers = self._create_transactions_and_update_balances(block_metadata)
        LOGGER.info(
            "Updating blockchain transaction block numbers for blockchain %s, block number %d",
            self.blockchain,
            block_metadata.block_number,
        )
        self._update_blockchain_transaction_block_numbers(block_number, transaction_identifiers)
        LOGGER.info(
            "Tracking new key currencies blockchain %s, block number %d", self.blockchain, block_metadata.block_number
        )
        self._track_new_key_currencies(block_metadata)
        LOGGER.info(
            "Updating key currency commitments for blockchain %s, block number %d",
            self.blockchain,
            block_metadata.block_number,
        )
        self._update_key_currency_commitments(block_metadata)
        with self.sessionmaker() as session:
            now_confirmed_block = (
                session.query(Block)
                .filter(
                    Block.block_number == block_number - (self.num_confirmations - 1),
                    Block.blockchain == self.blockchain,
                )
                .one_or_none()
            )
            if now_confirmed_block is not None:
                self._update_pending_balance(now_confirmed_block.block_number)
            row_count = (
                session.query(Block)
                .filter(
                    Block.blockchain == self.blockchain,
                    Block.block_number == block_number,
                )
                .update({Block.processed: True})
            )
            assert row_count == 1
            session.commit()

    @abstractmethod
    def deposit(self, address: str, currency: Currency, amount: Decimal) -> HexBytes:
        # issue a blockchain deposit into `address` of `amount` in `currency`
        # it should get the currency from outside Sancus -- e.g. via a faucet, mining, or
        # buying on a third-party exchange
        raise NotImplementedError()

    @abstractmethod
    def get_withdrawal_address(self, currency: Currency) -> str:
        # get an address to withdraw `currency` from Sancus.
        # it should be an address outside of sancus -- e.g a new random address,
        # or a deposit address on a third-party exchange
        raise NotImplementedError()
