import logging
import uuid
from decimal import Decimal
from typing import Mapping, Optional

import sqlalchemy.orm
from common.constants import CURRENCY_TO_BLOCKCHAIN, Blockchain, Currency
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from sqlalchemy import desc
from sqlalchemy.orm import Session

from auditor.sql.block import Block
from auditor.utils.blockchain_client.btc import BTCClient
from auditor.utils.blockchain_client.eth import ETHClient
from auditor.utils.blockchain_client.vendor_base import (
    BlockMetadata,
    VendorBaseBlockchainClient,
)

LOGGER = logging.getLogger(__name__)


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

    def validate_tx_in_chain(
        self,
        blockchain: Blockchain,
        txn_hash: HexBytes,
        tx_params: Any,
    ) -> None:
        self._blockchain_to_client[blockchain].validate_tx_in_chain(txn_hash, tx_params)

    def get_start_block_number(self, blockchain: Blockchain) -> int:
        return self._blockchain_to_client[blockchain].start_block_number

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

    def process_block(self, blockchain: Blockchain, block_number: int) -> None:
        return self._blockchain_to_client[blockchain].process_block(block_number)

    def is_new_transaction(self, blockchain: Blockchain, block_metadata: BlockMetadata, tx_params: Any) -> bool:
        return self._blockchain_to_client[blockchain].is_new_transaction(block_metadata, tx_params)

    def get_cumulative_deposits(
        self,
        key_uuid: uuid.UUID,
        currency: Currency,
        from_block_number: int,
        to_block_number: int,
    ) -> Decimal:
        LOGGER.info(
            "Getting cumulative deposits for key %s, currency %s, from block %d to %d",
            key_uuid,
            currency,
            from_block_number,
            to_block_number,
        )
        return self._blockchain_to_client[CURRENCY_TO_BLOCKCHAIN[currency]].get_cumulative_deposits(
            key_uuid,
            currency,
            from_block_number,
            to_block_number,
        )

    def get_balance_from_chain(
        self, session: Session, address: str, currency: Currency, block_metadata: BlockMetadata
    ) -> Decimal:
        return self._blockchain_to_client[CURRENCY_TO_BLOCKCHAIN[currency]].get_balance_from_chain(
            session,
            address,
            currency,
            block_metadata,
        )

    def initialize(self) -> None:
        for client in self._blockchain_to_client.values():
            client.initialize()
