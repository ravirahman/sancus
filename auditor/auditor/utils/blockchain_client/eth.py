import logging
import os
import uuid
from datetime import datetime
from decimal import Decimal
from threading import Lock
from typing import Dict, Mapping, Sequence, Set, cast

import pytz
import sqlalchemy.orm
import web3
import web3.eth
from common.config import W3Config
from common.constants import CURRENCY_PRECISIONS, Blockchain, Currency
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from protobufs.eth_pb2 import EthereumTxParams
from sqlalchemy.orm import Session
from web3.gas_strategies.rpc import rpc_gas_price_strategy
from web3.types import TxData, TxReceipt

from auditor.sql.blockchain_address_key import BlockchainAddressKey
from auditor.utils.blockchain_client.vendor_base import (
    BlockMetadata,
    TransactionNotFoundException,
    VendorBaseBlockchainClient,
)


def _get_erc20_abi() -> str:
    with open(os.path.join(os.path.dirname(__file__), "erc20abi.json"), "r") as f:
        return f.read()


LOGGER = logging.getLogger(__name__)

ERC20_ABI = _get_erc20_abi()


class ETHClient(VendorBaseBlockchainClient):
    def __init__(self, config: W3Config, sessionmaker: sqlalchemy.orm.sessionmaker) -> None:
        self._sessionmaker = sessionmaker
        assert config.start_block_number is not None, "None start block not supported for auditor"
        super().__init__(max_workers=config.max_workers, config_start_block_number=config.start_block_number)
        w3 = web3.Web3(provider=config.provider, middlewares=config.middlewares)
        w3.eth.setGasPriceStrategy(rpc_gas_price_strategy)
        self._w3 = w3
        self._stablecoin_to_contract: Dict[Currency, web3.contract.Contract] = {}
        self._contract_address_to_stablecoin: Dict[str, Currency] = {}
        for currency, address in config.stablecoin_to_erc20_contract_address.items():
            self._stablecoin_to_contract[currency] = self._w3.eth.contract(address=address, abi=ERC20_ABI)
            self._contract_address_to_stablecoin[address] = currency

    blockchain = Blockchain.ETH

    @property
    def sessionmaker(self) -> sqlalchemy.orm.sessionmaker:
        return self._sessionmaker

    @staticmethod
    def wei_to_eth(wei: int) -> Decimal:
        return Decimal(wei) / Decimal(10 ** 18)

    @staticmethod
    def eth_to_wei(eth: Decimal) -> int:
        amount_wei_dec = eth * Decimal(10 ** 18)
        amount_wei = int(eth * Decimal(10 ** 18))
        if Decimal(amount_wei) != amount_wei_dec:
            raise ValueError("Incorrect precision")
        return amount_wei

    def get_latest_block_number_from_chain(self) -> int:
        return int(self._w3.eth.block_number)

    def get_block_metadata_from_chain(self, block_number: int) -> BlockMetadata:
        block_data = self._w3.eth.get_block(block_number)
        return BlockMetadata(
            block_number=block_data["number"],
            block_timestamp=datetime.fromtimestamp(block_data["timestamp"], pytz.UTC),
            block_hash=block_data["hash"],
            parent_block_hash=block_data["parentHash"],
        )

    def get_balance_from_chain(
        self, session: Session, address: str, currency: Currency, block_metadata: BlockMetadata
    ) -> Decimal:
        if currency == Currency.ETH:
            bal_wei = self._w3.eth.get_balance(address, block_metadata.block_hash.hex())
            bal = self.wei_to_eth(bal_wei)
            return bal
        amount_int = (
            self._stablecoin_to_contract[currency]
            .functions.balanceOf(address)
            .call(block_identifier=block_metadata.block_hash.hex())
        )
        bal = Decimal(amount_int) / Decimal(CURRENCY_PRECISIONS[currency])
        return bal

    def _process_eth_key_address_for_deposits(
        self,
        *,
        block_metadata: BlockMetadata,
        key_uuid: uuid.UUID,
        ethereum_address: str,
        address_to_withdrawn_amount: Mapping[str, Decimal],
        key_uuid_to_deposit_amount: Dict[uuid.UUID, Decimal],
    ) -> None:
        LOGGER.debug(
            "Processing eth deposits for key(%s), address(%s), block(%d)",
            key_uuid,
            ethereum_address,
            block_metadata.block_number,
        )
        current_bal_wei = self._w3.eth.get_balance(ethereum_address, block_metadata.block_hash.hex())
        current_bal = self.wei_to_eth(current_bal_wei)
        previous_bal_wei = self._w3.eth.get_balance(ethereum_address, block_metadata.parent_block_hash.hex())
        previous_bal = self.wei_to_eth(previous_bal_wei)
        withdrawn_amount = address_to_withdrawn_amount.get(ethereum_address, Decimal(0))
        current_bal_without_new_deposits = previous_bal - withdrawn_amount
        assert current_bal >= current_bal_without_new_deposits, "invariant violation!!"
        deposited_amount = current_bal - current_bal_without_new_deposits
        if deposited_amount > Decimal(0):
            key_uuid_to_deposit_amount[key_uuid] = deposited_amount

    def _create_eth_transactions(self, transactions: Sequence[TxData], block_metadata: BlockMetadata) -> None:
        address_to_withdrawn_amount: Dict[str, Decimal] = {}
        mutex = Lock()
        with self._pool:
            for transaction in transactions:

                def process(transaction: TxData = transaction) -> None:
                    from_address = transaction["from"]
                    value = transaction["value"]
                    gas_price = transaction["gasPrice"]
                    tx_receipt = cast(TxReceipt, self._w3.eth.getTransactionReceipt(transaction["hash"]))
                    gas = tx_receipt["gasUsed"]
                    status = tx_receipt["status"]
                    # gas is spent regardless of whether successful and value is ONLY transferred if successful
                    amount = status * value + gas * gas_price
                    with mutex:
                        if from_address not in address_to_withdrawn_amount:
                            address_to_withdrawn_amount[from_address] = Decimal(0)
                        value_dec = self.wei_to_eth(amount)
                        address_to_withdrawn_amount[from_address] += value_dec

                self._pool(process)

        # TODO use evm transaction tracing instead of querying all accounts to get deposits
        key_uuid_to_deposit_amount: Dict[uuid.UUID, Decimal] = {}
        key_uuid_to_ethereum_address: Dict[uuid.UUID, str] = {}
        LOGGER.debug("Fetching all keys from the database")
        with self._sessionmaker() as session:
            LOGGER.info("Fetching key currency accounts from the database")
            blockchain_address_keys = (
                session.query(BlockchainAddressKey).filter(BlockchainAddressKey.blockchain == Blockchain.ETH).all()
            )
            key_uuid_to_ethereum_address = {bak.key_uuid: bak.address for bak in blockchain_address_keys}

        with self._pool:
            for key_uuid, ethereum_address in key_uuid_to_ethereum_address.items():

                def bound_process_eth_key_address_for_deposits(
                    key_uuid: uuid.UUID = key_uuid, ethereum_address: str = ethereum_address
                ) -> None:
                    self._process_eth_key_address_for_deposits(
                        block_metadata=block_metadata,
                        key_uuid=key_uuid,
                        ethereum_address=ethereum_address,
                        address_to_withdrawn_amount=address_to_withdrawn_amount,
                        key_uuid_to_deposit_amount=key_uuid_to_deposit_amount,
                    )

                self._pool(bound_process_eth_key_address_for_deposits)

        with self.sessionmaker() as session:
            withdrawal_blockchain_address_keys = (
                session.query(BlockchainAddressKey)
                .filter(
                    BlockchainAddressKey.blockchain == Blockchain.ETH,
                    BlockchainAddressKey.address.in_(address_to_withdrawn_amount.keys()),
                )
                .all()
            )
            key_uuid_to_withdrawal_amount = {
                bak.key_uuid: address_to_withdrawn_amount[bak.address] for bak in withdrawal_blockchain_address_keys
            }
        self._update_key_currency_block(
            Currency.ETH,
            key_uuid_to_withdrawal_amount,
            key_uuid_to_deposit_amount,
            block_metadata.block_number,
        )

    def _process_deposits_and_withdrawals(self, block_metadata: BlockMetadata) -> None:
        block_data = self._w3.eth.get_block(block_metadata.block_hash.hex(), full_transactions=True)
        assert block_data["number"] == block_metadata.block_number, "blockchain forked"
        transactions = block_data["transactions"]
        self._create_erc20_transactions(block_metadata)
        self._create_eth_transactions(transactions, block_metadata)

    def _create_erc20_transactions(self, block_metadata: BlockMetadata) -> None:
        """
        _create_erc20_transactions() looks at all the erc20 transactions for each tracked currency in the block.
        If the block has a deposit to a tracked erc20 address, then we call self._create_deposit_transaction() for
        each deposit. We also tally the cumulative delta for deposits and withdrawals for each tracked addresses
        in this block, which then calls self._update_key_currency_block()
        #"""
        for currency, contract in self._stablecoin_to_contract.items():
            key_uuid_to_withdrawn_amount: Dict[uuid.UUID, Decimal] = {}
            key_uuid_to_deposited_amount: Dict[uuid.UUID, Decimal] = {}
            transfer_filter = contract.events.Transfer.createFilter(
                fromBlock=block_metadata.block_number,  # TODO is it possible to use the block hash??
                toBlock=block_metadata.block_number,  # TODO is it possible to use the block hash??
            )
            transfers = transfer_filter.get_all_entries()
            addresses_to_query: Set[str] = set()
            for transfer in transfers:
                from_address = transfer["args"]["from"]
                to_address = transfer["args"]["to"]
                addresses_to_query.add(from_address)
                addresses_to_query.add(to_address)
            with self._sessionmaker() as session:
                blockchain_address_keys = (
                    session.query(BlockchainAddressKey)
                    .filter(
                        BlockchainAddressKey.blockchain == Blockchain.ETH,
                        BlockchainAddressKey.address.in_(addresses_to_query),
                    )
                    .all()
                )
                address_to_key_uuid = {bak.address: bak.key_uuid for bak in blockchain_address_keys}

            for transfer in transfers:
                from_address = transfer["args"]["from"]
                to_address = transfer["args"]["to"]
                amount_int = transfer["args"]["value"]
                amount = Decimal(amount_int) / Decimal(CURRENCY_PRECISIONS[currency])
                if to_address in address_to_key_uuid:
                    to_key_uuid = address_to_key_uuid[to_address]
                    if to_key_uuid not in key_uuid_to_deposited_amount:
                        key_uuid_to_deposited_amount[to_key_uuid] = Decimal(0)
                    key_uuid_to_deposited_amount[to_key_uuid] += amount
                if from_address in address_to_key_uuid:
                    from_key_uuid = address_to_key_uuid[from_address]
                    if from_key_uuid not in key_uuid_to_withdrawn_amount:
                        key_uuid_to_withdrawn_amount[from_key_uuid] = Decimal(0)
                    key_uuid_to_withdrawn_amount[from_key_uuid] += amount
            self._update_key_currency_block(
                currency,
                key_uuid_to_withdrawn_amount,
                key_uuid_to_deposited_amount,
                block_metadata.block_number,
            )

    def is_new_transaction(self, block_metadata: BlockMetadata, tx_params: Any) -> bool:
        eth_tx_params = EthereumTxParams()
        if not tx_params.Unpack(eth_tx_params):
            raise ValueError("unable to unpack tx_params to eth_tx_params")
        # validate that tx nonce is sufficiently high
        minimum_nonce = self._w3.eth.get_transaction_count(
            eth_tx_params.fromAddress,
            # block_identifier=block_metadata.block_number,
        )
        is_new_transaction = eth_tx_params.nonce >= minimum_nonce
        return is_new_transaction

    def validate_tx_in_chain(self, txn_hash: HexBytes, tx_params: Any) -> None:
        eth_tx_params = EthereumTxParams()
        if not tx_params.Unpack(eth_tx_params):
            raise TransactionNotFoundException("Unable to unpack tx_params to eth_tx_params")
        try:
            tx_data = cast(TxData, self._w3.eth.get_transaction(txn_hash))
        except web3.exceptions.TransactionNotFound as ex:
            raise TransactionNotFoundException("Transaction not found") from ex
        # Must have the value, nonce, from, to, gas, and data params match.
        filtered_found_tx_params = EthereumTxParams(
            value=tx_data["value"],
            gas=tx_data["gas"],
            nonce=tx_data["nonce"],
            toAddress=tx_data["to"],
            fromAddress=tx_data["from"],
            data=HexBytes(tx_data["input"]),
        )
        filtered_expected_tx_params = EthereumTxParams(
            value=eth_tx_params.value,
            gas=eth_tx_params.gas,
            nonce=eth_tx_params.nonce,
            toAddress=eth_tx_params.toAddress,
            fromAddress=eth_tx_params.fromAddress,
            data=eth_tx_params.data,
        )
        if filtered_found_tx_params != filtered_expected_tx_params:
            raise TransactionNotFoundException(
                f"Found tx params({filtered_found_tx_params}) != expected_tx_params({filtered_expected_tx_params})"
            )
        # it is ok if the gas price differs
