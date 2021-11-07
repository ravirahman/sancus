import logging
import uuid
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal
from typing import Dict, Generator, List, Tuple

import bitcoin
import bitcoin.rpc
import pytz
import sqlalchemy.orm
from bitcoin.core import COIN
from bitcoin.wallet import CBitcoinAddress, CBitcoinAddressError
from common.config import BTCProxyConfig
from common.constants import Blockchain, Currency
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from protobufs.bitcoin_pb2 import (
    BitcoinTransactionDestination,
    BitcoinTransactionSource,
    BitcoinTxParams,
)
from sqlalchemy import or_, tuple_
from sqlalchemy.orm import Session

from auditor.sql.blockchain_address_key import BlockchainAddressKey
from auditor.sql.btc_vout import BTCVout
from auditor.utils.blockchain_client.vendor_base import (
    BlockMetadata,
    TransactionNotFoundException,
    VendorBaseBlockchainClient,
)

BYTES_PER_KB = 1024

LOGGER = logging.getLogger(__name__)


class BTCClient(VendorBaseBlockchainClient):
    def __init__(self, sessionmaker: sqlalchemy.orm.sessionmaker, config: BTCProxyConfig) -> None:
        self._sessionmaker = sessionmaker
        assert config.start_block_number is not None, "None start block not supported for auditor"
        super().__init__(max_workers=config.max_workers, config_start_block_number=config.start_block_number)
        bitcoin.SelectParams(config.btc_node_type)
        self._config = config

    @contextmanager
    def _get_proxy(self) -> Generator[bitcoin.rpc.Proxy, None, None]:  # type: ignore[misc]
        proxy = bitcoin.rpc.Proxy(self._config.btc_service_url)
        try:
            yield proxy
        finally:
            proxy.close()

    blockchain = Blockchain.BTC

    @property
    def sessionmaker(self) -> sqlalchemy.orm.sessionmaker:
        return self._sessionmaker

    def get_block_metadata_from_chain(self, block_number: int) -> BlockMetadata:
        with self._get_proxy() as proxy:
            block_hash = HexBytes(proxy.getblockhash(block_number))
            block_data = proxy.getblock(block_hash)
            parent_block_hash = HexBytes(block_data.hashPrevBlock)
            block_timestamp = datetime.fromtimestamp(block_data.nTime, pytz.UTC)
        return BlockMetadata(
            block_number=block_number,
            block_hash=block_hash,
            parent_block_hash=parent_block_hash,
            block_timestamp=block_timestamp,
        )

    def get_balance_from_chain(
        self, session: Session, address: str, currency: Currency, block_metadata: BlockMetadata
    ) -> Decimal:
        btc_vouts = (
            session.query(BTCVout)
            .filter(
                BTCVout.address == address,
                BTCVout.block_number <= block_metadata.block_number,
                or_(
                    BTCVout.spent_block_number.is_(None),
                    BTCVout.spent_block_number > block_metadata.block_number,
                ),
            )
            .all()
        )

        balance = Decimal("0")

        for btc_vout in btc_vouts:
            balance += btc_vout.amount
        return balance

    def get_latest_block_number_from_chain(self) -> int:
        with self._get_proxy() as proxy:
            block_count = proxy.getblockcount()
        assert isinstance(block_count, int)
        return block_count

    def is_new_transaction(self, block_metadata: BlockMetadata, tx_params: Any) -> bool:
        btc_tx_params = BitcoinTxParams()
        if not tx_params.Unpack(btc_tx_params):
            raise ValueError("unable to unpack tx_params to btc_tx_params")
        # validate that all tx in's are unspent at the block
        with self._sessionmaker() as session:
            is_new_transaction: bool = (
                session.query(BTCVout)
                .filter(
                    tuple_(BTCVout.txid, BTCVout.voutindex).in_(
                        [(source.txid, source.vout) for source in btc_tx_params.sources]
                    ),
                    BTCVout.spent_block_number < block_metadata.block_number,
                )
                .limit(1)
                .count()
                == 0
            )
            return is_new_transaction

    def validate_tx_in_chain(self, txn_hash: HexBytes, tx_params: Any) -> None:
        btc_tx_params = BitcoinTxParams()
        if not tx_params.Unpack(btc_tx_params):
            raise TransactionNotFoundException("Unable to unpack tx_params to btc_tx_params")
        with self._get_proxy() as proxy:
            tx_data = proxy.getrawtransaction(txn_hash)
        # require that the tx vin's and vout's are a superset of the tx_param's vins and vouts
        tx_vins: List[BitcoinTransactionSource] = []
        tx_vouts: List[BitcoinTransactionDestination] = []
        for vin in tx_data.vin:
            tx_vins.append(BitcoinTransactionSource(txid=vin.prevout.hash, vout=vin.prevout.n))
        for vout in tx_data.vout:
            tx_vouts.append(
                BitcoinTransactionDestination(
                    value=str((Decimal(vout.nValue) / Decimal(COIN)).normalize()),
                    toAddress=str(CBitcoinAddress.from_scriptPubKey(vout.scriptPubKey)),
                )
            )
        for source in btc_tx_params.sources:
            if source not in tx_vins:
                raise TransactionNotFoundException(f"tx source {source} not found")
        for destination in btc_tx_params.destinations:
            if destination not in tx_vouts:
                raise TransactionNotFoundException(f"tx destination {destination} not found")

    def get_public_key(self, transaction_id: str) -> bytes:
        raise NotImplementedError()

    def _process_deposits_and_withdrawals(self, block_metadata: BlockMetadata) -> None:
        with self._get_proxy() as proxy:
            block_data = proxy.getblock(block_metadata.block_hash)

        address_to_block_deposit_amount: Dict[str, Decimal] = {}
        # tracking withdrawals so we can update balances
        txid_and_vout_indices: List[Tuple[HexBytes, int]] = []
        for tx_data in block_data.vtx:
            txid = HexBytes(tx_data.GetTxid())
            for vin in tx_data.vin:
                prevout = vin.prevout
                if prevout.is_null():
                    continue
                vin_txid, voutindex = HexBytes(prevout.hash), prevout.n
                txid_and_vout_indices.append((vin_txid, voutindex))
            for voutindex, vout in enumerate(tx_data.vout):
                script_pub_key = vout.scriptPubKey
                amount = Decimal(vout.nValue) / Decimal(COIN)
                if script_pub_key.is_witness_scriptpubkey():
                    # we don't support witness transactions (yet!)
                    continue
                if not script_pub_key.is_valid():
                    continue
                if script_pub_key.is_unspendable():
                    continue
                if script_pub_key.GetSigOpCount(fAccurate=True) != 1:
                    continue
                if script_pub_key.is_p2sh():
                    continue

                try:
                    address = str(CBitcoinAddress.from_scriptPubKey(vout.scriptPubKey))
                except CBitcoinAddressError:
                    pass

                if address not in address_to_block_deposit_amount:
                    address_to_block_deposit_amount[address] = Decimal(0)
                address_to_block_deposit_amount[address] += amount
                with self._sessionmaker() as session:  # TODO parallelize?
                    session.add(
                        BTCVout(
                            address=address,
                            txid=txid,
                            voutindex=voutindex,
                            amount=amount,
                            block_number=block_metadata.block_number,
                        )
                    )
                    try:
                        session.commit()
                    except sqlalchemy.exc.IntegrityError:
                        # if this happens, then we already have the vout. that's fine
                        pass
        with self._sessionmaker() as session:
            vouts_query = session.query(BTCVout).filter(
                tuple_(
                    BTCVout.txid,
                    BTCVout.voutindex,
                ).in_(txid_and_vout_indices)
            )
            vouts = vouts_query.all()
            vouts_query.update(
                {
                    BTCVout.spent_block_number: block_metadata.block_number,
                }
            )
            session.commit()
            address_to_block_withdrawal_amount: Dict[str, Decimal] = {}
            for vout in vouts:
                amount_decrement, address = vout.amount, vout.address
                if address not in address_to_block_withdrawal_amount:
                    address_to_block_withdrawal_amount[address] = Decimal(0)
                address_to_block_withdrawal_amount[address] += amount_decrement

            blockchain_address_keys = (
                session.query(BlockchainAddressKey)
                .filter(
                    BlockchainAddressKey.address.in_(
                        [*address_to_block_deposit_amount.keys(), *address_to_block_withdrawal_amount.keys()]
                    ),
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                )
                .all()
            )
            address_to_key_uuid: Dict[str, uuid.UUID] = {}
            for blockchain_address_key in blockchain_address_keys:
                address_to_key_uuid[blockchain_address_key.address] = blockchain_address_key.key_uuid

        key_uuid_to_deposit_amount: Dict[uuid.UUID, Decimal] = {}
        for address, deposited_amount in address_to_block_deposit_amount.items():
            if address not in address_to_key_uuid:
                continue
            key_uuid_to_deposit_amount[address_to_key_uuid[address]] = deposited_amount

        key_uuid_to_withdrawn_amount: Dict[uuid.UUID, Decimal] = {}
        for address, withdrawn_amount in address_to_block_withdrawal_amount.items():
            if address not in address_to_key_uuid:
                continue
            key_uuid_to_withdrawn_amount[address_to_key_uuid[address]] = withdrawn_amount
        self._update_key_currency_block(
            Currency.BTC,
            key_uuid_to_withdrawn_amount,
            key_uuid_to_deposit_amount,
            block_metadata.block_number,
        )
