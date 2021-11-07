import logging
import os
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from threading import Lock
from typing import TYPE_CHECKING, Dict, List, Mapping, Sequence, Set, Tuple, cast

import eth_account
import pytz
import sqlalchemy.orm
import web3
import web3.eth
from common.constants import ADMIN_UUID, CURRENCY_PRECISIONS, Blockchain, Currency
from common.utils.datetime import get_current_datetime
from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_account._utils.transactions import ALLOWED_TRANSACTION_KEYS
from eth_account._utils.transactions import Transaction as ETHTransaction
from eth_account._utils.transactions import serializable_unsigned_transaction_from_dict
from eth_keys import KeyAPI
from eth_utils.conversions import to_int
from eth_utils.crypto import keccak
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from protobufs.eth_pb2 import EthereumTxParams
from sqlalchemy import tuple_
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from web3.gas_strategies.rpc import rpc_gas_price_strategy
from web3.types import TxData, TxParams, TxReceipt

from backend.config import ETHConfig
from backend.sql.blockchain_address_key import BlockchainAddressKey
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.key import Key
from backend.sql.key_currency_account import KeyCurrencyAccount
from backend.utils.blockchain_client.vendor_base import (
    BlockMetadata,
    FundsUnavailableException,
    VendorBaseBlockchainClient,
)
from backend.utils.key_client import KeyClient
from backend.utils.profilers import record_txn_hash

if TYPE_CHECKING:
    from protobufs.institution.account_pb2 import (  # pylint: disable=ungrouped-imports
        KeyType,
    )


def _get_erc20_abi() -> str:
    with open(os.path.join(os.path.dirname(__file__), "erc20abi.json"), "r") as f:
        return f.read()


ERC20_ABI = _get_erc20_abi()
LOGGER = logging.getLogger(__name__)


class BadKeyException(Exception):
    pass


class ETHClient(VendorBaseBlockchainClient):
    def __init__(self, config: ETHConfig, key_client: KeyClient, sessionmaker: sqlalchemy.orm.sessionmaker) -> None:
        self._w3 = web3.Web3(provider=config.w3_config.provider, middlewares=config.w3_config.middlewares)
        self._w3.eth.setGasPriceStrategy(rpc_gas_price_strategy)
        self._num_confirmations = config.num_confirmations
        self._chain_id = config.w3_config.chain_id
        self._default_address = config.default_address
        self._sessionmaker = sessionmaker
        super().__init__(config.w3_config.max_workers, config.w3_config.start_block_number)
        self._rebroadcast_interval = config.rebroadcast_interval
        self._key_client = key_client
        self._transaction_timeout = config.transaction_timeout
        self._stablecoin_to_contract: Dict[Currency, web3.contract.Contract] = {}
        self._contract_address_to_stablecoin: Dict[str, Currency] = {}
        for currency, address in config.w3_config.stablecoin_to_erc20_contract_address.items():
            self._stablecoin_to_contract[currency] = self._w3.eth.contract(address=address, abi=ERC20_ABI)
            self._contract_address_to_stablecoin[address] = currency

    def deposit(self, address: str, currency: Currency, amount: Decimal) -> HexBytes:
        LOGGER.info("Depositing %s %s into %s", amount, currency, address)
        if currency == Currency.ETH:
            tx_params = {
                "from": self._default_address,
                "to": address,
                "value": self.eth_to_wei(amount),
            }
        else:
            tx_params = (
                self._stablecoin_to_contract[currency]
                .functions.transfer(address, int(amount * CURRENCY_PRECISIONS[currency]))
                .buildTransaction(
                    {
                        "from": self._default_address,
                    }
                )
            )
        txn_hash = self._w3.eth.send_transaction(tx_params)
        return HexBytes(txn_hash)

    def get_withdrawal_address(self, currency: Currency) -> str:
        return self._default_address

    @property
    def rebroadcast_interval(self) -> timedelta:
        return self._rebroadcast_interval

    blockchain = Blockchain.ETH

    @property
    def sessionmaker(self) -> sqlalchemy.orm.sessionmaker:
        return self._sessionmaker

    @property
    def key_client(self) -> KeyClient:
        return self._key_client

    @property
    def num_confirmations(self) -> int:
        return self._num_confirmations

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

    def _get_gas_price(self) -> int:
        gas_price = self._w3.eth.generateGasPrice()
        if isinstance(gas_price, int):
            return gas_price
        if isinstance(gas_price, str) and gas_price.startswith("0x"):  # type: ignore[unreachable]
            return int(gas_price, 16)  # type: ignore[unreachable]
        raise TypeError("invalid type for gas_price")

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

    def _get_balance_from_chain(
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

    def get_public_key(self, transaction_id: str) -> HexBytes:
        tx_data: web3.types.TxData = self._w3.eth.get_transaction(transaction_id)
        # https://ethereum.stackexchange.com/questions/2166/retrieve-the-signature-of-a-transaction-on-the-blockchain
        chain_id, v_bit = extract_chain_id(tx_data.v)
        signature = KeyAPI.Signature(vrs=(to_standard_v(v_bit), to_int(tx_data.r), to_int(tx_data.s)))
        new_tx: TxData = {}
        for key in ALLOWED_TRANSACTION_KEYS:
            if key == "data":
                new_tx["data"] = tx_data.input
                continue
            if key == "chainId":
                new_tx["chainId"] = chain_id
                continue
            new_tx[key] = tx_data[key]
        unsigned_tx = serializable_unsigned_transaction_from_dict(new_tx)
        public_key: KeyAPI.PublicKey = signature.recover_public_key_from_msg_hash(unsigned_tx.hash())
        public_key_bytes = public_key.to_bytes()
        assert isinstance(public_key_bytes, bytes)
        return HexBytes(public_key_bytes)

    def _process_eth_key_address_for_deposits(
        self,
        *,
        block_metadata: BlockMetadata,
        key_uuid: uuid.UUID,
        ethereum_address: str,
        address_to_withdrawn_amount: Mapping[str, Decimal],
        key_uuid_to_deposit_amount: Dict[uuid.UUID, Decimal],
        key_uuid_to_account_uuid: Mapping[uuid.UUID, uuid.UUID],
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
            account_uuid = key_uuid_to_account_uuid[key_uuid]
            if account_uuid != ADMIN_UUID:
                blockchain_transaction_identifier = self._create_transaction_identifier(
                    {
                        b"TYPE": b"DEPOSIT",
                        b"CURRENCY": b"ETH",
                        b"KEY_UUID": key_uuid.bytes,
                        b"BLOCK_HASH": block_metadata.block_hash,
                    }
                )
                self._create_deposit_transaction(
                    block_metadata.block_number,
                    block_metadata.block_timestamp,
                    blockchain_transaction_identifier,
                    account_uuid,
                    deposited_amount,
                )

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
        key_uuid_to_account_uuid: Dict[uuid.UUID, uuid.UUID] = {}
        LOGGER.info("Fetching all keys from the database")
        with self._sessionmaker() as session:
            LOGGER.info("Fetching key currency accounts from the database")
            key_currency_accounts = (
                session.query(KeyCurrencyAccount.key_uuid, KeyCurrencyAccount.account_uuid)
                .filter(
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .all()
            )
            key_uuids: List[uuid.UUID] = []
            for key_uuid, account_uuid in key_currency_accounts:
                key_uuids.append(key_uuid)
                key_uuid_to_account_uuid[key_uuid] = account_uuid
            blockchain_address_keys = (
                session.query(BlockchainAddressKey)
                .filter(BlockchainAddressKey.key_uuid.in_(key_uuids), BlockchainAddressKey.blockchain == Blockchain.ETH)
                .all()
            )
            key_uuid_to_ethereum_address = {bak.key_uuid: bak.address for bak in blockchain_address_keys}
        LOGGER.info("Processing the keys one by one")

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
                        key_uuid_to_account_uuid=key_uuid_to_account_uuid,
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

    def _reconcile_withdrawal_gas(self, block_number: int, txn_hashes: Sequence[HexBytes]) -> None:
        for txn_hash in txn_hashes:
            with self._sessionmaker() as session:
                # set the block number for transactions that have hit the chain
                row_count = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        BlockchainWithdrawal.txn_hash == txn_hash,
                        BlockchainWithdrawal.block_number.is_(None),
                        BlockchainWithdrawal.blockchain == Blockchain.ETH,
                    )
                    .update(
                        {
                            BlockchainWithdrawal.block_number: block_number,
                        }
                    )
                )
                if row_count == 0:
                    continue  # either it's an unrelated txn hash, or we already processed it
                pending_tx = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        BlockchainWithdrawal.txn_hash == txn_hash,
                        BlockchainWithdrawal.blockchain == Blockchain.ETH,
                    )
                    .one()
                )
                tx_receipt = cast(TxReceipt, self._w3.eth.getTransactionReceipt(txn_hash))
                gas_used = tx_receipt["gasUsed"]
                status = tx_receipt["status"]
                if status == 0:
                    raise RuntimeError("Status was 0!!!! This should NEVER happen.")
                tx_params_any_pb = pending_tx.tx_params
                tx_params = EthereumTxParams()
                if not tx_params_any_pb.Unpack(tx_params):
                    raise RuntimeError("Unable to unpack tx_params to EthereumTxParams")
                gas_alloted = tx_params.gas
                gas_price_wei = tx_params.gasPrice
                gas_credit_wei = gas_price_wei * (gas_alloted - gas_used)
                gas_credit_eth = self.wei_to_eth(gas_credit_wei)

                key = (
                    session.query(Key)
                    .filter(
                        BlockchainAddressKey.blockchain == Blockchain.ETH,
                        BlockchainAddressKey.address == tx_params.fromAddress,
                        BlockchainAddressKey.key_uuid == Key.key_uuid,
                    )
                    .one()
                )
                key_uuid = key.key_uuid
                # update the key-currency's available balance to reflect actual transaction fees
                key_currency_account = (
                    session.query(KeyCurrencyAccount)
                    .filter(
                        KeyCurrencyAccount.key_uuid == key_uuid,
                        KeyCurrencyAccount.currency == Currency.ETH,  # all tx fees are in ETH
                    )
                    .populate_existing()
                    .with_for_update()
                    .one()
                )

                key_currency_account.available_balance += gas_credit_eth
                session.commit()

    def _create_transactions_and_update_balances(self, block_metadata: BlockMetadata) -> Sequence[HexBytes]:
        block_data = self._w3.eth.get_block(block_metadata.block_hash.hex(), full_transactions=True)
        assert block_data["number"] == block_metadata.block_number, "blockchain forked"
        block_number = block_metadata.block_number
        transactions = block_data["transactions"]
        txn_hashes = [tx["hash"] for tx in transactions]
        LOGGER.info("Creating erc20 deposit transactions for ETH block %d", block_metadata.block_number)
        self._create_erc20_transactions(block_metadata)
        LOGGER.info("Creating eth deposit transactions for ETH block %d", block_metadata.block_number)
        self._create_eth_transactions(transactions, block_metadata)
        LOGGER.info("Reconciling withdrawal gas for ETH block %d", block_metadata.block_number)
        self._reconcile_withdrawal_gas(block_number, txn_hashes)
        LOGGER.info("Pending admin deposits for ETH block %d", block_metadata.block_number)
        self._update_pending_admin_deposits(block_number)
        LOGGER.info("Rebroadcasting transactions for ETH block %d", block_metadata.block_number)
        self._rebroadcast_transactions()
        LOGGER.info("Broadcasting new transactions for ETH block %d", block_metadata.block_number)
        self._broadcast_new_transactions()
        LOGGER.info("Voiding expired transactions for ETH block %d", block_metadata.block_number)
        self._void_expired_pending_transactions()
        LOGGER.info("Creating withdrawal transaction identifiers ETH block %d", block_metadata.block_number)
        transaction_identifiers = [self._create_withdrawal_transaction_identifier(txn_hash) for txn_hash in txn_hashes]
        return transaction_identifiers

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
                keys = (
                    session.query(Key)
                    .filter(
                        BlockchainAddressKey.blockchain == Blockchain.ETH,
                        BlockchainAddressKey.address.in_(addresses_to_query),
                        BlockchainAddressKey.key_uuid == Key.key_uuid,
                    )
                    .all()
                )
                address_to_key_uuid = {key.get_address(Blockchain.ETH): key.key_uuid for key in keys}

                key_currency_accounts = (
                    session.query(KeyCurrencyAccount)
                    .filter(
                        KeyCurrencyAccount.currency == currency,
                        KeyCurrencyAccount.key_uuid.in_(address_to_key_uuid.values()),
                    )
                    .all()
                )
                key_uuid_to_account_uuid = {kca.key_uuid: kca.account_uuid for kca in key_currency_accounts}
            for transfer in transfers:
                from_address = transfer["args"]["from"]
                to_address = transfer["args"]["to"]
                amount_int = transfer["args"]["value"]
                amount = Decimal(amount_int) / Decimal(CURRENCY_PRECISIONS[currency])
                transaction_hash = transfer["transactionHash"]
                log_index = transfer["logIndex"]
                if to_address in address_to_key_uuid:
                    to_key_uuid = address_to_key_uuid[to_address]
                    if to_key_uuid in key_uuid_to_account_uuid:
                        to_account_uuid = key_uuid_to_account_uuid[to_key_uuid]
                        if to_account_uuid != ADMIN_UUID:
                            blockchain_transaction_identifier = self._create_transaction_identifier(
                                {
                                    b"TYPE": b"DEPOSIT",
                                    b"CURRENCY": bytes(currency.name, "utf8"),
                                    b"KEY_UUID": to_key_uuid.bytes,
                                    b"TRANSACTION_HASH": transaction_hash,
                                    b"LOG_INDEX": bytes(str(log_index), "utf8"),
                                }
                            )
                            self._create_deposit_transaction(
                                block_metadata.block_number,
                                block_metadata.block_timestamp,
                                blockchain_transaction_identifier,
                                to_account_uuid,
                                amount,
                            )
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

    def _serialize_tx_params(self, transaction: TxParams) -> EthereumTxParams:
        assert transaction["chainId"] == self._chain_id
        data = HexBytes(transaction["data"])
        return EthereumTxParams(
            value=transaction["value"],
            chainId=transaction["chainId"],
            toAddress=transaction["to"],
            gas=transaction["gas"],
            gasPrice=transaction["gasPrice"],
            nonce=transaction["nonce"],
            data=data,
            fromAddress=transaction["from"],
        )

    def _deserialize_tx_params(self, transaction: EthereumTxParams) -> TxParams:
        assert transaction.chainId == self._chain_id
        return {
            "value": transaction.value,
            "chainId": transaction.chainId,
            "to": transaction.toAddress,
            "nonce": transaction.nonce,
            "gas": transaction.gas,
            "gasPrice": transaction.gasPrice,
            "data": transaction.data,
            "from": transaction.fromAddress,
        }

    def _create_unsigned_eth_transaction(
        self,
        session: Session,
        amount: Decimal,
        destination_address: str,
        key_type: "KeyType.V",
    ) -> Tuple[uuid.UUID, Any]:
        gas = 21_000
        gas_price = self._get_gas_price()
        tx_fee_wei = gas * gas_price
        gas_eth = self.wei_to_eth(tx_fee_wei)
        total_cost = amount + gas_eth
        bad_keys: List[uuid.UUID] = []
        while True:
            candidate = (
                session.query(KeyCurrencyAccount.key_uuid, KeyCurrencyAccount.available_balance)
                .filter(
                    KeyCurrencyAccount.currency == Currency.ETH,
                    KeyCurrencyAccount.account_uuid.isnot(None),  # is not Anonymous
                    KeyCurrencyAccount.approximate_available_balance >= float(total_cost),  # type: ignore[operator]
                    Key.key_type == key_type,
                    KeyCurrencyAccount.key_uuid == Key.key_uuid,
                    Key.key_uuid.notin_(bad_keys),
                )
                .order_by(KeyCurrencyAccount.approximate_available_balance)
                .first()
            )
            if candidate is None:
                break
            key_uuid, candidate_available_balance = candidate
            assert isinstance(candidate_available_balance, Decimal)
            if candidate_available_balance < total_cost:
                bad_keys.append(key_uuid)
                continue
            session.begin_nested()
            try:
                try:
                    key = (
                        session.query(Key)
                        .filter(
                            Key.key_uuid == key_uuid,
                        )
                        .populate_existing()
                        .with_for_update(nowait=True)
                        .one()
                    )
                    key_currency = (
                        session.query(KeyCurrencyAccount)
                        .filter(
                            KeyCurrencyAccount.key_uuid == key_uuid,
                            KeyCurrencyAccount.currency == Currency.ETH,
                        )
                        .populate_existing()
                        .with_for_update(nowait=True)
                        .one()
                    )
                except OperationalError as e:
                    raise BadKeyException() from e

                # double-check the balance again
                available_balance = key_currency.available_balance
                assert isinstance(available_balance, Decimal)
                if available_balance < total_cost:
                    raise BadKeyException()
                transaction_nonce = key.ethereum_transaction_count
                tx_params = {
                    "to": destination_address,
                    "from": key.get_address(Blockchain.ETH),
                    "value": self.eth_to_wei(amount),
                    "gas": gas,  # default gas for eth transfer,
                    "gasPrice": gas_price,
                    "chainId": self._chain_id,
                    "nonce": transaction_nonce,
                    "data": b"",
                }

                tx_params_pb = self._serialize_tx_params(tx_params)
                tx_params_any_pb = Any()
                tx_params_any_pb.Pack(tx_params_pb)
                blockchain_withdrawal = BlockchainWithdrawal(
                    expires_at=get_current_datetime() + self._transaction_timeout,
                    tx_params=tx_params_any_pb,
                    blockchain=Blockchain.ETH,
                )
                session.add(blockchain_withdrawal)
                key.ethereum_transaction_count += 1
                key_currency.available_balance = available_balance - total_cost
                session.commit()  # commit the begin-nested
                return blockchain_withdrawal.uuid, tx_params_any_pb
            except BadKeyException:
                bad_keys.append(key_uuid)
                session.rollback()
            except Exception:
                session.rollback()
                raise

        raise FundsUnavailableException(
            "Unable to find a suitable key for the withdrawal size. "
            "Please try a smaller withdrawal or try again later."
        )

    def _get_transaction_currency(self, tx_params: EthereumTxParams) -> Currency:
        if tx_params.toAddress in self._contract_address_to_stablecoin:
            assert tx_params.value == 0
            return self._contract_address_to_stablecoin[tx_params.toAddress]
        assert tx_params.data == b""
        return Currency.ETH

    def _get_transaction_destination_and_amount(self, tx_params: EthereumTxParams) -> Tuple[str, Decimal]:
        if tx_params.toAddress in self._contract_address_to_stablecoin:
            assert tx_params.value == 0
            currency = self._get_transaction_currency(tx_params)
            ignored_function, input_data = self._stablecoin_to_contract[currency].decode_function_input(tx_params.data)
            address = input_data["_to"]
            value = input_data["_value"]
            return address, Decimal(value) / Decimal(CURRENCY_PRECISIONS[currency])
        assert tx_params.data == b""
        return tx_params.toAddress, self.wei_to_eth(tx_params.value)

    def _update_pending_admin_deposits(self, block_number: int) -> None:
        with self._sessionmaker() as session:
            now_confirmed_transactions_uuids = (
                session.query(BlockchainWithdrawal.uuid)
                .filter(
                    BlockchainWithdrawal.block_number <= block_number - (self._num_confirmations - 1),
                    BlockchainWithdrawal.blockchain == Blockchain.ETH,
                    BlockchainWithdrawal.pending_admin_deposits_reconciled.is_(False),
                )
                .all()
            )
        # get the destination address from the tx params
        for (now_confirmed_transactions_uuid,) in now_confirmed_transactions_uuids:
            with self._sessionmaker() as session:
                now_confirmed_transaction = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        BlockchainWithdrawal.uuid == now_confirmed_transactions_uuid,
                        BlockchainWithdrawal.block_number <= block_number - (self._num_confirmations - 1),
                        BlockchainWithdrawal.blockchain == Blockchain.ETH,
                        BlockchainWithdrawal.pending_admin_deposits_reconciled.is_(False),
                    )
                    .populate_existing()
                    .with_for_update()
                    .one_or_none()
                )
                if now_confirmed_transaction is None:
                    continue
                tx_params_pb = EthereumTxParams()
                if not now_confirmed_transaction.tx_params.Unpack(tx_params_pb):
                    raise RuntimeError("Unable to unpack pb")
                currency = self._get_transaction_currency(tx_params_pb)
                address, ignored_amount = self._get_transaction_destination_and_amount(tx_params_pb)
                key = (
                    session.query(Key)
                    .filter(
                        BlockchainAddressKey.blockchain == Blockchain.ETH,
                        BlockchainAddressKey.address == address,
                        BlockchainAddressKey.key_uuid == Key.key_uuid,
                    )
                    .one_or_none()
                )
                if key is None:
                    continue
                # If the following query is a NO-OP, then it wasn't an internal transfer
                session.query(KeyCurrencyAccount).filter(
                    KeyCurrencyAccount.key_uuid == key.key_uuid,
                    KeyCurrencyAccount.currency == currency,
                    KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                ).update(
                    {
                        KeyCurrencyAccount.pending_admin_deposits: KeyCurrencyAccount.pending_admin_deposits - 1,
                    }
                )
                now_confirmed_transaction.pending_admin_deposits_reconciled = True
                session.commit()

    def _create_unsigned_erc20_transaction(
        self,
        session: Session,
        amount: Decimal,
        currency: Currency,
        destination_address: str,
        key_type: "KeyType.V",
    ) -> Tuple[uuid.UUID, Any]:
        contract = self._stablecoin_to_contract[currency]
        amount_int = int(amount * CURRENCY_PRECISIONS[currency])
        if Decimal(amount_int) != amount * CURRENCY_PRECISIONS[currency]:
            raise RuntimeError("amount is too precise")
        bad_keys: List[uuid.UUID] = []
        gas_price = self._get_gas_price()
        gas = 200_000  # TODO
        transaction_fee_wei = gas_price * gas
        transaction_fee = self.wei_to_eth(transaction_fee_wei)
        while True:
            result = (
                session.query(Key.key_uuid, KeyCurrencyAccount.available_balance)
                .filter(
                    KeyCurrencyAccount.currency == currency,
                    KeyCurrencyAccount.account_uuid.isnot(None),  # is not Anonymous
                    KeyCurrencyAccount.approximate_available_balance >= float(amount),  # type: ignore[operator]
                    Key.key_type == key_type,
                    Key.key_uuid == KeyCurrencyAccount.key_uuid,
                    Key.key_uuid.notin_(bad_keys),
                )
                .order_by(KeyCurrencyAccount.approximate_available_balance)
                .first()
            )
            if result is None:
                break
            key_uuid, candidate_available_balance = result
            assert isinstance(candidate_available_balance, Decimal)
            assert isinstance(key_uuid, uuid.UUID)
            if candidate_available_balance < amount:
                bad_keys.append(key_uuid)
                continue
            (candidate_eth_available_balance,) = (
                session.query(KeyCurrencyAccount.available_balance)
                .filter(
                    KeyCurrencyAccount.currency == Currency.ETH,
                    KeyCurrencyAccount.key_uuid == key_uuid,
                )
                .one()
            )
            assert isinstance(candidate_eth_available_balance, Decimal)
            if candidate_eth_available_balance < transaction_fee:
                bad_keys.append(key_uuid)
                continue
            session.begin_nested()
            try:
                # attempt lock the key and key currency accounts.
                # if the lock fails, that's fine. Move on to the next key.
                # using a session.begin_nested() so we can release the locks
                # if need be and move on to the next key
                try:
                    key = (
                        session.query(Key)
                        .filter(
                            Key.key_uuid == key_uuid,
                        )
                        .populate_existing()
                        .with_for_update(nowait=True)
                        .one()
                    )
                    key_currency = (
                        session.query(KeyCurrencyAccount)
                        .filter(
                            KeyCurrencyAccount.key_uuid == key_uuid,
                            KeyCurrencyAccount.currency == currency,
                        )
                        .populate_existing()
                        .with_for_update(nowait=True)
                        .one()
                    )
                    eth_key_currency = (
                        session.query(KeyCurrencyAccount)
                        .filter(
                            KeyCurrencyAccount.key_uuid == key_uuid,
                            KeyCurrencyAccount.currency == Currency.ETH,
                        )
                        .populate_existing()
                        .with_for_update(nowait=True)
                        .one()
                    )
                except OperationalError as e:  # failed to aquire locks
                    raise BadKeyException() from e
                available_balance = key_currency.available_balance
                assert available_balance is not None
                eth_available_balance = eth_key_currency.available_balance
                assert eth_available_balance is not None
                # double check the balances again
                if available_balance < amount:
                    raise BadKeyException()
                if eth_available_balance < transaction_fee:
                    raise BadKeyException()

                transaction_nonce = key.ethereum_transaction_count
                tx_params = contract.functions.transfer(destination_address, amount_int).buildTransaction(
                    {
                        "from": key.get_address(Blockchain.ETH),
                        "gas": gas,  # default gas for eth transfer,
                        "gasPrice": gas_price,
                        "chainId": self._chain_id,
                        "nonce": transaction_nonce,
                        "value": 0,
                    }
                )
                tx_params_pb = self._serialize_tx_params(tx_params)
                any_pb = Any()
                any_pb.Pack(tx_params_pb)
                blockchain_withdrawal = BlockchainWithdrawal(
                    expires_at=get_current_datetime() + self._transaction_timeout,
                    tx_params=any_pb,
                    blockchain=Blockchain.ETH,
                )
                session.add(blockchain_withdrawal)
                key.ethereum_transaction_count += 1
                key_currency.available_balance = available_balance - amount
                eth_key_currency.available_balance = eth_available_balance - transaction_fee
                session.commit()
                return blockchain_withdrawal.uuid, any_pb
            except BadKeyException:
                bad_keys.append(key_uuid)
                session.rollback()
            except Exception:
                session.rollback()
                raise
        raise RuntimeError("Cannot find a key for the withdrawal size. Try a smaller amount or try again later.")

    def _broadcast_transaction(self, signed_tx: HexBytes) -> HexBytes:
        try:
            self._w3.eth.send_raw_transaction(signed_tx)
        except ValueError:
            # The ethereum node is flakey. Let's ignore errors here.
            pass
        transaction_hash = HexBytes(keccak(signed_tx))
        record_txn_hash(Blockchain.ETH, transaction_hash)
        return transaction_hash

    def create_pending_transaction(
        self,
        session: Session,
        amount: Decimal,
        currency: Currency,
        destination_address: str,
        key_type: "KeyType.V",
        should_dest_be_admin: bool,
    ) -> Tuple[uuid.UUID, Any]:
        dest_key = (
            session.query(Key)
            .filter(
                BlockchainAddressKey.blockchain == Blockchain.ETH,
                BlockchainAddressKey.address == destination_address,
                BlockchainAddressKey.key_uuid == Key.key_uuid,
                KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                KeyCurrencyAccount.currency == currency,
                KeyCurrencyAccount.key_uuid == BlockchainAddressKey.key_uuid,
            )
            .one_or_none()
        )
        if should_dest_be_admin and dest_key is None:
            raise RuntimeError("dest key not admin")
        if should_dest_be_admin and dest_key is not None:
            row_count = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == dest_key.key_uuid,
                    KeyCurrencyAccount.currency == currency,
                    KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                )
                .update(
                    {
                        KeyCurrencyAccount.pending_admin_deposits: KeyCurrencyAccount.pending_admin_deposits + 1,
                    }
                )
            )
            assert row_count == 1
        if not should_dest_be_admin and dest_key is not None:
            raise RuntimeError("dest key not specified as admin but it is!!!")
        if currency == Currency.ETH:
            return self._create_unsigned_eth_transaction(session, amount, destination_address, key_type)
        return self._create_unsigned_erc20_transaction(session, amount, currency, destination_address, key_type)

    def _void_expired_pending_transactions(self) -> None:
        # when voiding a transaction, we replace it with a transfer to a firm-controlled account.
        # this is because transaction nonces must be sequentail, and we never reduce the
        # key.ethereum_transaction_nonce field
        with self._sessionmaker() as session:
            unsigned_transaction_uuids = (
                session.query(BlockchainWithdrawal.uuid)
                .filter(
                    BlockchainWithdrawal.expires_at < get_current_datetime(),
                    BlockchainWithdrawal.signed_tx.is_(None),
                    BlockchainWithdrawal.blockchain == Blockchain.ETH,
                )
                .all()
            )

        for (unsigned_transaction_uuid,) in unsigned_transaction_uuids:
            with self._sessionmaker() as session:
                unsigned_transaction = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        BlockchainWithdrawal.uuid == unsigned_transaction_uuid,
                        BlockchainWithdrawal.expires_at < get_current_datetime(),
                        BlockchainWithdrawal.signed_tx.is_(None),
                        BlockchainWithdrawal.blockchain == Blockchain.ETH,
                    )
                    .populate_existing()
                    .with_for_update()
                    .one_or_none()
                )
                if unsigned_transaction is None:
                    continue
                dest_key = self._key_client.find_or_create_admin_key(session, Currency.ETH)
                dest_eth_address = dest_key.get_address(Blockchain.ETH)
                # replace it with a dummy to use up the nonce
                # broadcast it immediately
                # TODO if we have to burn, is there a cheaper way to burn?
                # TODO instead of burning nonces, re-use them whenever possible!
                old_tx_params_any_pb = unsigned_transaction.tx_params
                old_tx_params = EthereumTxParams()
                if not old_tx_params_any_pb.Unpack(old_tx_params):
                    raise RuntimeError("Unable to unpack EthereumTxParams from any")
                original_currency = self._get_transaction_currency(old_tx_params)
                ignored_original_destination, original_tx_amount = self._get_transaction_destination_and_amount(
                    old_tx_params
                )
                new_value_wei = 1  # TODO replacing with a value that protects plausible deniability
                new_value = self.wei_to_eth(new_value_wei)
                gas = 21_000
                gas_price_wei = self._get_gas_price()
                estimated_tx_fee_wei = gas * gas_price_wei
                estimated_tx_fee = self.wei_to_eth(estimated_tx_fee_wei)
                new_tx_params = {
                    "to": dest_eth_address,
                    "from": old_tx_params.fromAddress,
                    "value": new_value_wei,
                    "gas": gas,  # default gas for eth transfer,
                    "gasPrice": gas_price_wei,  # use whatever the new gas price is
                    "chainId": self._chain_id,
                    "nonce": old_tx_params.nonce,
                    "data": b"",
                }
                new_tx_params_pb = self._serialize_tx_params(new_tx_params)
                # get the key, and sign it if it is Hot
                key = (
                    session.query(Key)
                    .filter(
                        BlockchainAddressKey.blockchain == Blockchain.ETH,
                        BlockchainAddressKey.address == old_tx_params.fromAddress,
                        BlockchainAddressKey.key_uuid == Key.key_uuid,
                    )
                    .one()
                )
                key_uuid = key.key_uuid
                private_key_bn = key.private_key
                if private_key_bn is None:
                    signed_tx = None
                else:
                    account = eth_account.account.Account.from_key(  # pylint: disable=no-value-for-parameter
                        private_key_bn.binary().rjust(32, b"\0")
                    )
                    signed_tx = account.sign_transaction(new_tx_params).rawTransaction

                # let's lock all the key currency accounts we would want
                # 1. (key_uuid, original currency) -- if the original currency isn't eth
                # 2. (key_uuid, ETH)
                # 3. (to_key_currency.key_uuid, to_key_currency.currency) -- if needed
                # 4. (dest_key, ETH)
                key_currencies_to_lock = [
                    (key_uuid, Currency.ETH),
                    (dest_key.key_uuid, Currency.ETH),
                ]
                if original_currency != Currency.ETH:
                    key_currencies_to_lock.append((key_uuid, original_currency))

                # if the original to address was admin, decrement the pending admin deposits
                to_key_uuid_and_currency = (
                    session.query(KeyCurrencyAccount.key_uuid, KeyCurrencyAccount.currency)
                    .filter(
                        BlockchainAddressKey.address == old_tx_params.toAddress,
                        KeyCurrencyAccount.key_uuid == BlockchainAddressKey.key_uuid,
                        KeyCurrencyAccount.currency == original_currency,
                    )
                    .one_or_none()
                )
                if to_key_uuid_and_currency is not None:
                    key_currencies_to_lock.append(to_key_uuid_and_currency)

                # get the locks together to prevent a deadlock
                key_currency_accounts = (
                    session.query(KeyCurrencyAccount)
                    .filter(
                        tuple_(KeyCurrencyAccount.key_uuid, KeyCurrencyAccount.currency).in_(key_currencies_to_lock)
                    )
                    .populate_existing()
                    .with_for_update()
                    .all()
                )
                key_currency_to_object = {(kca.key_uuid, kca.currency): kca for kca in key_currency_accounts}

                if to_key_uuid_and_currency is not None:
                    to_key_currency = key_currency_to_object[to_key_uuid_and_currency]
                    if to_key_currency.account_uuid == ADMIN_UUID:
                        to_kca = key_currency_to_object[(to_key_currency.key_uuid, original_currency)]
                        assert to_kca.pending_admin_deposits > 0
                        to_kca.pending_admin_deposits -= 1
                # mark the admin account as having an internal deposit
                admin_kca = key_currency_to_object[(dest_key.key_uuid, Currency.ETH)]
                admin_kca.pending_admin_deposits += 1

                original_estimated_tx_fee = self.wei_to_eth(old_tx_params.gas * old_tx_params.gasPrice)

                eth_key_currency_account = key_currency_to_object[(key_uuid, Currency.ETH)]

                # add back the old fee, and subtract the new fee and the dummy value
                new_eth_available_bal = (
                    eth_key_currency_account.available_balance
                    + original_estimated_tx_fee
                    - estimated_tx_fee
                    - new_value
                )
                if original_currency == Currency.ETH:
                    # if the previous currency was ETH, credit back the full amount
                    new_eth_available_bal += self.wei_to_eth(old_tx_params.value)

                eth_kca = key_currency_to_object[(key_uuid, Currency.ETH)]
                eth_kca.available_balance = new_eth_available_bal

                if original_currency != Currency.ETH:
                    currency_key_currency_account = key_currency_to_object[(key_uuid, original_currency)]

                    currency_key_currency_account.available_balance += original_tx_amount

                new_tx_params_any_pb = Any()
                new_tx_params_any_pb.Pack(new_tx_params_pb)

                unsigned_transaction.tx_params = new_tx_params_any_pb
                unsigned_transaction.signed_tx = signed_tx
                session.commit()

    def _deserialize_signed_transaction(self, signed_transaction: HexBytes) -> EthereumTxParams:
        rlp_dict = ETHTransaction.from_bytes(signed_transaction).as_dict()
        # see https://eips.ethereum.org/EIPS/eip-155
        assert rlp_dict["v"] > 35, "EIP-155 signatures required"
        chain_id = (rlp_dict["v"] - 35) // 2
        rlp_dict["chainId"] = chain_id
        recovered_from_address = eth_account.Account.recover_transaction(  # pylint: disable=no-value-for-parameter
            signed_transaction
        )
        rlp_dict["from"] = recovered_from_address
        rlp_dict["to"] = self._w3.toChecksumAddress(rlp_dict["to"])
        # validate the parameters are the same
        serialized_tx_params_from_rlp = self._serialize_tx_params(rlp_dict)
        return serialized_tx_params_from_rlp

    def queue_cold_transaction(
        self, session: Session, transaction_id: uuid.UUID, signed_transaction: HexBytes
    ) -> HexBytes:
        blockchain_withdrawal = (
            session.query(BlockchainWithdrawal)
            .filter(
                BlockchainWithdrawal.uuid == transaction_id,
                BlockchainWithdrawal.signed_tx.is_(None),
            )
            .populate_existing()
            .with_for_update()
            .one()
        )
        tx_params_any_pb = blockchain_withdrawal.tx_params
        tx_params_pb = EthereumTxParams()
        if not tx_params_any_pb.Unpack(tx_params_pb):
            raise RuntimeError("Unable to unpack any pb")
        # validate the parameters are the same
        serialized_tx_params_from_rlp = self._deserialize_signed_transaction(signed_transaction)
        transaction_hash = HexBytes(keccak(signed_transaction))
        if serialized_tx_params_from_rlp != tx_params_pb:
            raise ValueError("signed_transaction doesn't match tx_params in DB")
        # validate that the signature is correct
        blockchain_withdrawal.signed_tx = signed_transaction
        return self._create_withdrawal_transaction_identifier(transaction_hash)

    def get_cold_transactions_awaiting_signature(self) -> Sequence[Any]:
        raise NotImplementedError()

    def queue_hot_transaction(self, session: Session, transaction_id: uuid.UUID) -> HexBytes:
        blockchain_withdrawal = (
            session.query(BlockchainWithdrawal)
            .filter(
                BlockchainWithdrawal.uuid == transaction_id,
                BlockchainWithdrawal.signed_tx.is_(None),
            )
            .populate_existing()
            .with_for_update()
            .one()
        )
        tx_params_any_pb = blockchain_withdrawal.tx_params
        tx_params_pb = EthereumTxParams()
        if not tx_params_any_pb.Unpack(tx_params_pb):
            raise RuntimeError("Unable to unpack any pb")

        key = (
            session.query(Key)
            .filter(
                BlockchainAddressKey.blockchain == Blockchain.ETH,
                BlockchainAddressKey.address == tx_params_pb.fromAddress,
                BlockchainAddressKey.key_uuid == Key.key_uuid,
            )
            .one()
        )
        tx_params = self._deserialize_tx_params(tx_params_pb)
        private_key_bn = key.private_key
        if private_key_bn is None:
            raise ValueError("TransactionID corresponds to a cold key, not a hot key")
        account = eth_account.account.Account.from_key(  # pylint: disable=no-value-for-parameter
            private_key_bn.binary().rjust(32, b"\0")
        )
        signed_tx = account.sign_transaction(tx_params)
        signed_transaction = signed_tx.rawTransaction
        blockchain_withdrawal.signed_tx = signed_transaction
        return self._create_withdrawal_transaction_identifier(signed_tx.hash)
