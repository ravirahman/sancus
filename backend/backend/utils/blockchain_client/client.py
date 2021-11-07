import logging
import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Mapping, Optional, Sequence, Tuple

import sqlalchemy.orm
from common.constants import CURRENCY_TO_BLOCKCHAIN, Blockchain, Currency
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.sql.block import Block
from backend.utils.blockchain_client.btc import BTCClient
from backend.utils.blockchain_client.eth import ETHClient
from backend.utils.blockchain_client.vendor_base import (
    BlockMetadata,
    VendorBaseBlockchainClient,
)
from backend.utils.profilers import record_latency_process_block

if TYPE_CHECKING:
    from protobufs.institution.account_pb2 import KeyType

LOGGER = logging.getLogger(__name__)


class NoBlockFoundException(Exception):
    pass


class BlockchainClient:
    def __init__(
        self,
        eth_client: ETHClient,
        btc_client: BTCClient,
        sessionmaker: sqlalchemy.orm.sessionmaker,
    ) -> None:
        self._blockchain_to_client: Mapping[Blockchain, VendorBaseBlockchainClient] = {
            Blockchain.ETH: eth_client,
            Blockchain.BTC: btc_client,
        }
        self._sessionmaker = sessionmaker

    def get_num_confirmations(self, blockchain: Blockchain) -> int:
        return self._blockchain_to_client[blockchain].num_confirmations

    def get_start_block_number(self, blockchain: Blockchain) -> int:
        return self._blockchain_to_client[blockchain].start_block_number

    def get_block_number_at_or_after_timestamp(self, blockchain: Blockchain, timestamp: datetime) -> int:
        with self._sessionmaker() as session:
            block_after_number_tuple = (
                session.query(Block.block_number)
                .filter(
                    Block.blockchain == blockchain,
                    Block.processed.is_(True),
                    Block.timestamp >= timestamp,
                )
                .order_by(Block.block_number)
                .first()
            )
            if block_after_number_tuple is None:
                raise NoBlockFoundException(f"No block found for blockchain {blockchain} after timestamp {timestamp}")
            (block_number,) = block_after_number_tuple
            assert isinstance(block_number, int)
            return block_number

    def get_latest_processed_block_timestamp_across_all_blockchains(self) -> datetime:
        earliest_block_timestamp: Optional[datetime] = None
        for blockchain in Blockchain:
            with self._sessionmaker() as session:
                block_timestamp_tuple = (
                    session.query(Block.timestamp)
                    .filter(
                        Block.processed.is_(True),
                        Block.blockchain == blockchain,
                    )
                    .order_by(desc(Block.block_number))
                    .first()
                )
                if block_timestamp_tuple is None:
                    raise NoBlockFoundException(f"No block found for blockchain {blockchain}")
                (block_timestamp,) = block_timestamp_tuple
                if earliest_block_timestamp is None or block_timestamp < earliest_block_timestamp:
                    earliest_block_timestamp = block_timestamp
        assert earliest_block_timestamp is not None
        return earliest_block_timestamp

    def get_latest_processed_block_number(self, blockchain: Blockchain) -> Optional[int]:
        with self._sessionmaker() as session:
            last_processed_block = (
                session.query(Block)
                .filter(
                    Block.blockchain == blockchain,
                    Block.processed.is_(True),
                )
                .order_by(desc(Block.block_number))
                .first()
            )
            if last_processed_block is None:
                return None
            assert isinstance(last_processed_block.block_number, int)
            return last_processed_block.block_number

    def get_latest_block_number_from_chain(self, blockchain: Blockchain) -> int:
        return self._blockchain_to_client[blockchain].get_latest_block_number_from_chain()

    def get_block_metadata_from_chain(self, blockchain: Blockchain, block_number: int) -> BlockMetadata:
        return self._blockchain_to_client[blockchain].get_block_metadata_from_chain(block_number)

    def queue_cold_transaction(
        self, session: Session, blockchain: Blockchain, transaction_id: uuid.UUID, signed_transaction: HexBytes
    ) -> HexBytes:
        # Returns the BlockchainTransactionIdentifier
        return self._blockchain_to_client[blockchain].queue_cold_transaction(
            session, transaction_id, signed_transaction
        )

    def queue_hot_transaction(self, session: Session, blockchain: Blockchain, transaction_id: uuid.UUID) -> HexBytes:
        # Returns the BlockchainTransactionIdentifier
        return self._blockchain_to_client[blockchain].queue_hot_transaction(session, transaction_id)

    def get_cold_transactions_awaiting_signature(self, blockchain: Blockchain) -> Sequence[Any]:
        return self._blockchain_to_client[blockchain].get_cold_transactions_awaiting_signature()

    @record_latency_process_block
    def process_block(self, blockchain: Blockchain, block_number: int) -> None:  # type: ignore[misc]
        return self._blockchain_to_client[blockchain].process_block(block_number)

    def get_cumulative_deposits(
        self,
        key_uuid: uuid.UUID,
        currency: Currency,
        from_block_number: int,
        to_block_number: int,
    ) -> Decimal:
        return self._blockchain_to_client[CURRENCY_TO_BLOCKCHAIN[currency]].get_cumulative_deposits(
            key_uuid,
            currency,
            from_block_number,
            to_block_number,
        )

    def create_pending_transaction(
        self,
        session: Session,
        amount: Decimal,
        currency: Currency,
        destination_address: str,
        key_type: "KeyType.V",
        should_dest_be_admin: bool,
    ) -> Tuple[uuid.UUID, Any]:
        return self._blockchain_to_client[CURRENCY_TO_BLOCKCHAIN[currency]].create_pending_transaction(
            session, amount, currency, destination_address, key_type, should_dest_be_admin
        )

    def deposit(self, address: str, currency: Currency, amount: Decimal) -> HexBytes:
        return self._blockchain_to_client[CURRENCY_TO_BLOCKCHAIN[currency]].deposit(
            address,
            currency,
            amount,
        )

    def get_withdrawal_address(self, currency: Currency) -> str:
        return self._blockchain_to_client[CURRENCY_TO_BLOCKCHAIN[currency]].get_withdrawal_address(currency)
