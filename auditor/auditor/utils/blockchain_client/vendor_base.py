import hashlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from decimal import Decimal
from typing import List, Mapping, NamedTuple, Sequence

import sqlalchemy.orm
from common.constants import CURRENCY_TO_BLOCKCHAIN, Blockchain, Currency
from common.utils.managed_thread_pool import ManagedThreadPool
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auditor.sql.block import Block
from auditor.sql.key_currency_block import KeyCurrencyBlock


class BlockMetadata(NamedTuple):
    block_number: int
    block_hash: HexBytes
    parent_block_hash: HexBytes
    block_timestamp: datetime


class TransactionNotFoundException(Exception):
    pass


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
            if start_block is not None and start_block.block_number != config_start_block_number:
                raise ValueError(
                    f"config.start_block({config_start_block_number}) != db start_block({start_block.block_number})"
                )
        self.start_block_number = config_start_block_number

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

    @property
    @abstractmethod
    def sessionmaker(self) -> sqlalchemy.orm.sessionmaker:
        raise NotImplementedError()

    @staticmethod
    def _create_transaction_identifier(data: Mapping[bytes, bytes]) -> str:
        data_list = list(data.items())
        data_list.sort(key=lambda x: x[0])  # sort by the keys, alphabetically
        m_digest = hashlib.sha256()
        for k, v in data_list:
            m_digest.update(k)
            m_digest.update(b"=")
            m_digest.update(v)
            m_digest.update(b",")
        return m_digest.hexdigest()

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

    def _add_key_currency_block(
        self,
        key_uuid: uuid.UUID,
        block_number: int,
        currency: Currency,
        withdrawal_amount: Decimal,
        deposit_amount: Decimal,
    ) -> None:
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
                prev_key_currency_block = self.get_key_currency_block(
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
                session.commit()

    def _update_key_currency_block(
        self,
        currency: Currency,
        key_uuid_to_withdrawal_amount: Mapping[uuid.UUID, Decimal],
        key_uuid_to_deposit_amount: Mapping[uuid.UUID, Decimal],
        block_number: int,
    ) -> None:
        key_uuids = set([*key_uuid_to_withdrawal_amount.keys(), *key_uuid_to_deposit_amount.keys()])
        with self._pool:
            for key_uuid in key_uuids:
                deposit_amount = key_uuid_to_deposit_amount.get(key_uuid, Decimal(0))
                withdrawal_amount = key_uuid_to_withdrawal_amount.get(key_uuid, Decimal(0))

                def bound_add_key_currency_block(
                    key_uuid: uuid.UUID = key_uuid,
                    deposit_amount: Decimal = deposit_amount,
                    withdrawal_amount: Decimal = withdrawal_amount,
                ) -> None:
                    self._add_key_currency_block(
                        key_uuid=key_uuid,
                        currency=currency,
                        block_number=block_number,
                        deposit_amount=deposit_amount,
                        withdrawal_amount=withdrawal_amount,
                    )

                self._pool(bound_add_key_currency_block)

    @abstractmethod
    def get_latest_block_number_from_chain(self) -> int:
        raise NotImplementedError()

    @abstractmethod
    def get_block_metadata_from_chain(self, block_number: int) -> BlockMetadata:
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
            from_key_currency_block = self.get_key_currency_block(session, key_uuid, currency, from_block_number - 1)
            to_key_currency_block = self.get_key_currency_block(session, key_uuid, currency, to_block_number)
            cumulative_tracked_deposit_amount = (
                to_key_currency_block.cumulative_tracked_deposit_amount
                - from_key_currency_block.cumulative_tracked_deposit_amount
            )
            assert isinstance(cumulative_tracked_deposit_amount, Decimal)
            return cumulative_tracked_deposit_amount

    def initialize(self) -> None:
        # nothing to initialize!
        pass

    @abstractmethod
    def get_balance_from_chain(
        self, session: Session, address: str, currency: Currency, block_metadata: BlockMetadata
    ) -> Decimal:
        raise NotImplementedError()

    @abstractmethod
    def validate_tx_in_chain(self, txn_hash: HexBytes, tx_params: Any) -> None:
        raise NotImplementedError()

    @abstractmethod
    def _process_deposits_and_withdrawals(self, block_metadata: BlockMetadata) -> None:
        # This function scan the block_metadata's block for deposits and withdrawals for tracked key currencies
        # And call self._update_key_currency_block() once for each currency
        raise NotImplementedError()

    @abstractmethod
    def is_new_transaction(self, block_metadata: BlockMetadata, tx_params: Any) -> bool:
        """
        whether a transaction containing `tx_params` is gauranteed NOT to be in the blockchain
        at any block, up to and including, `block_metadata`
        """
        raise NotImplementedError()

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
        self._process_deposits_and_withdrawals(block_metadata)
        with self.sessionmaker() as session:
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
