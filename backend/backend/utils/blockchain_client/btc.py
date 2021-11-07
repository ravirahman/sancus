import logging
import secrets
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from decimal import Decimal
from queue import Queue
from typing import TYPE_CHECKING, Dict, Generator, List, Sequence, Tuple

import bitcoin
import bitcoin.rpc
import petlib.bn
import petlib.ec
import pytz
import sqlalchemy.orm
from bitcoin.core import (
    COIN,
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    b2x,
)
from bitcoin.core.script import SIGHASH_ALL, CScript, SignatureHash
from bitcoin.core.scripteval import SCRIPT_VERIFY_P2SH, VerifyScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinAddressError, CBitcoinSecret
from common.constants import ADMIN_UUID, CURRENCY_PRECISIONS, Blockchain, Currency
from common.utils.datetime import get_current_datetime
from google.protobuf.any_pb2 import Any
from hexbytes.main import HexBytes
from protobufs.bitcoin_pb2 import (
    BitcoinTransactionDestination,
    BitcoinTransactionSource,
    BitcoinTxParams,
)
from sqlalchemy import or_, tuple_
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from backend.config import BTCConfig
from backend.sql.blockchain_address_key import BlockchainAddressKey
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.btc_vout import BTCVout
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

BYTES_PER_KB = 1024

LOGGER = logging.getLogger(__name__)


class BTCClient(VendorBaseBlockchainClient):
    def __init__(self, sessionmaker: sqlalchemy.orm.sessionmaker, config: BTCConfig, key_client: KeyClient) -> None:
        self.btc_proxy_pool: "Queue[None]" = Queue(config.proxy_config.max_workers)
        for _ in range(config.proxy_config.max_workers):
            self.btc_proxy_pool.put_nowait(None)

        bitcoin.SelectParams(config.proxy_config.btc_node_type)
        self._sessionmaker = sessionmaker
        self._config = config
        self._num_confirmations = config.num_confirmations
        self._rebroadcast_interval = config.rebroadcast_interval
        self._key_client = key_client
        self._transaction_timeout = config.transaction_timeout
        super().__init__(config.proxy_config.max_workers, config.proxy_config.start_block_number)
        LOGGER.info("Start block number: %s", self.start_block_number)

    def deposit(self, address: str, currency: Currency, amount: Decimal) -> HexBytes:
        LOGGER.info("Depositing %s %s into %s", amount, currency, address)
        with self._get_proxy() as proxy:
            txn_hash = proxy.sendtoaddress(address, int(amount * bitcoin.core.COIN))
            return HexBytes(txn_hash)

    def get_withdrawal_address(self, currency: Currency) -> str:
        with self._get_proxy() as proxy:
            return str(proxy.getnewaddress())

    @contextmanager
    def _get_proxy(self) -> Generator[bitcoin.rpc.Proxy, None, None]:  # type: ignore[misc]
        self.btc_proxy_pool.get(timeout=30)  # get a "Lock" for a proxy from the pool
        try:
            proxy = bitcoin.rpc.Proxy(self._config.proxy_config.btc_service_url, timeout=60)
            try:
                yield proxy
            finally:
                proxy.close()
        finally:
            self.btc_proxy_pool.put_nowait(None)

    @property
    def rebroadcast_interval(self) -> timedelta:
        return self._rebroadcast_interval

    blockchain = Blockchain.BTC

    @property
    def sessionmaker(self) -> sqlalchemy.orm.sessionmaker:
        return self._sessionmaker

    @property
    def num_confirmations(self) -> int:
        return self._num_confirmations

    @property
    def key_client(self) -> KeyClient:
        return self._key_client

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

    def _get_balance_from_chain(
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

    def get_public_key(self, transaction_id: str) -> bytes:
        raise NotImplementedError()

    def _create_deposit_transaction_identifer(self, txid: HexBytes, voutindex: int) -> HexBytes:
        return self._create_transaction_identifier(
            {
                b"TYPE": b"DEPOSIT",
                b"txid": txid,
                b"voutindex": str(voutindex).encode("utf8"),
            }
        )

    def _broadcast_transaction(self, signed_tx: HexBytes) -> HexBytes:
        max_fee = "0"
        with self._get_proxy() as proxy:
            try:
                proxy.call("sendrawtransaction", b2x(signed_tx), max_fee)
            except bitcoin.rpc.VerifyAlreadyInChainError:
                pass
            except bitcoin.rpc.VerifyError as e:
                if "bad-txns-inputs-missingorspent" not in str(e):
                    # we already broadcast this transaction; that's fine
                    raise e
        tx_id = HexBytes(CMutableTransaction.deserialize(signed_tx).GetTxid())
        record_txn_hash(Blockchain.BTC, tx_id)
        return tx_id

    def _void_expired_pending_transactions(self) -> None:
        with self._sessionmaker() as session:
            unsigned_transactions = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.expires_at < get_current_datetime(),
                    BlockchainWithdrawal.signed_tx.is_(None),
                    BlockchainWithdrawal.blockchain == Blockchain.BTC,
                )
                .all()
            )
        for unsigned_transaction in unsigned_transactions:
            tx_params_any_pb = unsigned_transaction.tx_params
            tx_params = BitcoinTxParams()
            if not tx_params_any_pb.Unpack(tx_params):
                raise RuntimeError("Unable to unpack PB")
            for source in tx_params.sources:
                with self._sessionmaker() as session:
                    txid = source.txid
                    voutindex = source.vout
                    btc_vout_and_key_currency = (
                        session.query(BTCVout, KeyCurrencyAccount)
                        .filter(
                            BTCVout.txid == txid,
                            BTCVout.voutindex == voutindex,
                            BlockchainAddressKey.address == BTCVout.address,
                            BlockchainAddressKey.key_uuid == KeyCurrencyAccount.key_uuid,
                            KeyCurrencyAccount.currency == Currency.BTC,
                        )
                        .populate_existing()
                        .with_for_update()
                        .one_or_none()
                    )
                    if btc_vout_and_key_currency is None:
                        # this means we already "unspent" it
                        continue
                    btc_vout, key_currency = btc_vout_and_key_currency
                    btc_vout.spent = False
                    key_currency.available_balance += btc_vout.amount
                    session.commit()  # mark the source as unspent

            destination_addresses = [destination.toAddress for destination in tx_params.destinations]
            with self._sessionmaker() as session:
                # not all destinations are admin so not validating the row count
                key_uuid_tuples: List[Tuple[uuid.UUID]] = (
                    session.query(BlockchainAddressKey.key_uuid)
                    .filter(
                        BlockchainAddressKey.address.in_(destination_addresses),
                        BlockchainAddressKey.blockchain == Blockchain.BTC,
                    )
                    .all()
                )

                key_uuids = [key_uuid for (key_uuid,) in key_uuid_tuples]

                session.query(KeyCurrencyAccount).filter(
                    KeyCurrencyAccount.key_uuid.in_(key_uuids),
                    KeyCurrencyAccount.currency == Currency.BTC,
                    KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                ).update(
                    {KeyCurrencyAccount.pending_admin_deposits: KeyCurrencyAccount.pending_admin_deposits - 1},
                    synchronize_session=False,
                )
                blockchain_withdrawal = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        BlockchainWithdrawal.uuid == unsigned_transaction.uuid,
                        BlockchainWithdrawal.signed_tx.is_(None),
                    )
                    .populate_existing()
                    .with_for_update()
                    .one()
                )
                session.delete(blockchain_withdrawal)
                session.commit()

    def _update_withdrawals(self, block_number: int, txn_hashes: Sequence[HexBytes]) -> None:
        with self._sessionmaker() as session:
            session.query(BlockchainWithdrawal).filter(
                BlockchainWithdrawal.txn_hash.in_(txn_hashes),
                BlockchainWithdrawal.block_number.is_(None),
                BlockchainWithdrawal.blockchain == Blockchain.BTC,
            ).update({BlockchainWithdrawal.block_number: block_number})
            session.commit()

    def _create_transactions_and_update_balances(
        self,
        block_metadata: BlockMetadata,
    ) -> Sequence[HexBytes]:
        with self._get_proxy() as proxy:
            block_data = proxy.getblock(block_metadata.block_hash)

        address_to_block_deposit_amount: Dict[str, Decimal] = {}
        address_to_deposit_bti_amounts: Dict[str, List[Tuple[HexBytes, Decimal]]] = {}
        # tracking withdrawals so we can update balances
        txid_and_vout_indices: List[Tuple[HexBytes, int]] = []
        for tx in block_data.vtx:
            txid = HexBytes(tx.GetTxid())
            for vin in tx.vin:
                prevout = vin.prevout
                if prevout.is_null():
                    continue
                vin_txid, voutindex = HexBytes(prevout.hash), prevout.n
                txid_and_vout_indices.append((vin_txid, voutindex))
            for voutindex, vout in enumerate(tx.vout):
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
                if address not in address_to_deposit_bti_amounts:
                    address_to_deposit_bti_amounts[address] = []
                with self._sessionmaker() as session:
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
                address_to_deposit_bti_amounts[address].append(
                    (
                        self._create_deposit_transaction_identifer(txid, voutindex),
                        amount,
                    )
                )
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
                    BTCVout.spent: True,
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

            blockchain_address_key_and_key_currency_accounts = (
                session.query(BlockchainAddressKey, KeyCurrencyAccount)
                .filter(
                    BlockchainAddressKey.address.in_(
                        [*address_to_block_deposit_amount.keys(), *address_to_block_withdrawal_amount.keys()]
                    ),
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                    BlockchainAddressKey.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .all()
            )
            address_to_key_uuid: Dict[str, uuid.UUID] = {}
            address_to_account_uuid: Dict[str, uuid.UUID] = {}
            for blockchain_address_key, key_currency_account in blockchain_address_key_and_key_currency_accounts:
                address_to_key_uuid[blockchain_address_key.address] = blockchain_address_key.key_uuid
                if key_currency_account.account_uuid is not None:
                    address_to_account_uuid[blockchain_address_key.address] = key_currency_account.account_uuid

        key_uuid_to_deposit_amount: Dict[uuid.UUID, Decimal] = {}
        for address, deposited_amount in address_to_block_deposit_amount.items():
            if address not in address_to_key_uuid:
                continue
            key_uuid_to_deposit_amount[address_to_key_uuid[address]] = deposited_amount

        for address, bti_amounts in address_to_deposit_bti_amounts.items():
            if address in address_to_account_uuid:
                account_uuid = address_to_account_uuid[address]
                if account_uuid == ADMIN_UUID:
                    continue
                for bti, amount in bti_amounts:
                    self._create_deposit_transaction(
                        block_metadata.block_number,
                        block_metadata.block_timestamp,
                        bti,
                        account_uuid,
                        amount,
                    )

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
        txn_hashes = [HexBytes(tx.GetTxid()) for tx in block_data.vtx]
        self._update_withdrawals(block_metadata.block_number, txn_hashes)
        self._update_pending_admin_deposits(block_metadata.block_number)
        self._rebroadcast_transactions()
        self._broadcast_new_transactions()
        self._void_expired_pending_transactions()
        transaction_identifiers = [self._create_withdrawal_transaction_identifier(txn_hash) for txn_hash in txn_hashes]
        return transaction_identifiers

    def _update_pending_admin_deposits(
        self,
        block_number: int,
    ) -> None:
        with self._sessionmaker() as session:
            now_confirmed_transactions_uuids = (
                session.query(BlockchainWithdrawal.uuid)
                .filter(
                    # subtracting 1 since if it's equal then that's 1 confirmation
                    BlockchainWithdrawal.block_number <= block_number - (self._num_confirmations - 1),
                    BlockchainWithdrawal.blockchain == Blockchain.BTC,
                    BlockchainWithdrawal.pending_admin_deposits_reconciled.is_(False),
                )
                .all()
            )
        for (now_confirmed_transaction_uuid,) in now_confirmed_transactions_uuids:
            with self._sessionmaker() as session:
                # not all keys will be updated if it's an internal transfer from one user in Sancus to another user
                # in Sancus.
                now_confirmed_transaction = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        # subtracting 1 since if it's equal then that's 1 confirmation
                        BlockchainWithdrawal.uuid == now_confirmed_transaction_uuid,
                        BlockchainWithdrawal.block_number <= block_number - (self._num_confirmations - 1),
                        BlockchainWithdrawal.blockchain == Blockchain.BTC,
                        BlockchainWithdrawal.pending_admin_deposits_reconciled.is_(False),
                    )
                    .populate_existing()
                    .with_for_update()
                    .one_or_none()
                )
                if now_confirmed_transaction is None:
                    continue
                tx_params_pb = BitcoinTxParams()
                if not now_confirmed_transaction.tx_params.Unpack(tx_params_pb):
                    raise RuntimeError("Unable to unpack pb")
                destination_addresses = [destination.toAddress for destination in tx_params_pb.destinations]

                key_uuid_tuples: List[Tuple[uuid.UUID]] = (
                    session.query(BlockchainAddressKey.key_uuid)
                    .filter(
                        BlockchainAddressKey.address.in_(destination_addresses),
                        BlockchainAddressKey.blockchain == Blockchain.BTC,
                    )
                    .all()
                )

                key_uuids = [key_uuid for (key_uuid,) in key_uuid_tuples]

                session.query(KeyCurrencyAccount).filter(
                    KeyCurrencyAccount.key_uuid.in_(key_uuids),
                    KeyCurrencyAccount.currency == Currency.BTC,
                    KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                ).update(
                    {
                        KeyCurrencyAccount.pending_admin_deposits: KeyCurrencyAccount.pending_admin_deposits - 1,
                    },
                    synchronize_session=False,
                )

                now_confirmed_transaction.pending_admin_deposits_reconciled = True
                session.commit()

    def _get_tx_fee_rate(self) -> Decimal:
        with self._get_proxy() as proxy:
            fee_rate_response = proxy.call("estimatesmartfee", 3)
        if "errors" in fee_rate_response:
            return Decimal(100000) / Decimal(CURRENCY_PRECISIONS[Currency.BTC])
        fee_rate = fee_rate_response["feerate"]
        assert not isinstance(fee_rate, float)
        return Decimal(fee_rate)

    @staticmethod
    def _calculate_tx_fee(*, num_inputs: int, num_outputs: int, tx_fee_rate: Decimal) -> Decimal:
        tx_fee_raw = (num_inputs * 181 + num_outputs * 34 + 10) * tx_fee_rate / BYTES_PER_KB
        tx_fee_quantized = tx_fee_raw.quantize(Decimal("1") / Decimal(COIN))
        return tx_fee_quantized

    def create_pending_transaction(
        self,
        session: Session,
        amount: Decimal,
        currency: Currency,
        destination_address: str,
        key_type: "KeyType.V",
        should_dest_be_admin: bool,
    ) -> Tuple[uuid.UUID, Any]:
        if currency != Currency.BTC:
            raise ValueError("Currency must be BTC")
        dest_key = (
            session.query(Key)
            .filter(
                BlockchainAddressKey.blockchain == Blockchain.BTC,
                BlockchainAddressKey.address == destination_address,
                BlockchainAddressKey.key_uuid == Key.key_uuid,
                KeyCurrencyAccount.account_uuid == ADMIN_UUID,
                KeyCurrencyAccount.key_uuid == BlockchainAddressKey.key_uuid,
            )
            .one_or_none()
        )
        if should_dest_be_admin and dest_key is None:
            raise RuntimeError("dest key not admin")

        # keeping track of all the key uuids we'll want to update, so we can do an orderly lock on them
        key_uuids_to_lock: List[uuid.UUID] = []

        if should_dest_be_admin and dest_key is not None:
            key_uuids_to_lock.append(dest_key.key_uuid)

        if not should_dest_be_admin and dest_key is not None:
            raise RuntimeError("dest key not specified as admin but it is!!!")
        tx_fee_rate = self._get_tx_fee_rate()  # in BTC/KB
        inputs: List[BitcoinTransactionSource] = []
        outputs = [BitcoinTransactionDestination(value=str(amount.normalize()), toAddress=destination_address)]
        input_amount = Decimal(0)
        input_address_to_amount: Dict[str, Decimal] = {}

        bad_txids: List[HexBytes] = []
        bad_voutindices: List[int] = []

        while True:
            query = session.query(BTCVout).filter(
                BTCVout.spent.is_(False),
                BTCVout.address == BlockchainAddressKey.address,
                BlockchainAddressKey.blockchain == Blockchain.BTC,
                BlockchainAddressKey.key_uuid == Key.key_uuid,
                Key.key_type == key_type,
                BTCVout.txid.notin_(bad_txids),
                BTCVout.voutindex.notin_(bad_voutindices),
            )
            count = query.count()
            if count == 0:
                raise FundsUnavailableException(
                    "Not enough bitcoin in the institution or it is locked up by existing pending transactions."
                )
            input_candidate = query.order_by(BTCVout.created_at).offset(secrets.randbelow(count)).first()
            assert input_candidate is not None
            try:
                row_count = (
                    session.query(BTCVout)
                    .filter(
                        BTCVout.txid == input_candidate.txid,
                        BTCVout.voutindex == input_candidate.voutindex,
                        BTCVout.spent.is_(False),
                    )
                    .update({BTCVout.spent: True})
                )
            except OperationalError:
                bad_txids.append(input_candidate.txid)
                bad_voutindices.append(input_candidate.voutindex)
                continue
            if row_count == 0:
                # race condition
                bad_txids.append(input_candidate.txid)
                bad_voutindices.append(input_candidate.voutindex)
                continue
            input_amount += input_candidate.amount
            if input_candidate.address not in input_address_to_amount:
                input_address_to_amount[input_candidate.address] = Decimal("0")
            input_address_to_amount[input_candidate.address] += input_candidate.amount
            inputs.append(BitcoinTransactionSource(txid=input_candidate.txid, vout=input_candidate.voutindex))
            if input_amount >= amount + self._calculate_tx_fee(
                num_inputs=len(inputs), num_outputs=2, tx_fee_rate=tx_fee_rate
            ):
                break
        excluded_key_uuids = []
        if dest_key is not None:
            excluded_key_uuids.append(dest_key.key_uuid)
        remainder_key = self._key_client.find_or_create_admin_key(
            session, Currency.BTC, excluded_key_uuids=excluded_key_uuids
        )
        key_uuids_to_lock.append(remainder_key.key_uuid)
        value = (
            input_amount
            - amount
            - self._calculate_tx_fee(num_inputs=len(inputs), num_outputs=2, tx_fee_rate=tx_fee_rate)
        )
        outputs.append(
            BitcoinTransactionDestination(
                value=str(value.normalize()),
                toAddress=remainder_key.get_address(Blockchain.BTC),
            )
        )
        bitcoin_tx_params = BitcoinTxParams(sources=inputs, destinations=outputs)
        address_to_key_uuid: Dict[str, uuid.UUID] = {}

        for input_address, address_amount in input_address_to_amount.items():
            (key_currency_key_uuid,) = (
                session.query(KeyCurrencyAccount.key_uuid)
                .filter(
                    BlockchainAddressKey.address == input_address,
                    BlockchainAddressKey.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            address_to_key_uuid[input_address] = key_currency_key_uuid
            key_uuids_to_lock.append(key_currency_key_uuid)

        tx_params_any_pb = Any()
        tx_params_any_pb.Pack(bitcoin_tx_params)
        pending_blockchain_transaction = BlockchainWithdrawal(
            expires_at=get_current_datetime() + self._transaction_timeout,
            tx_params=tx_params_any_pb,
            blockchain=Blockchain.BTC,
        )
        session.add(pending_blockchain_transaction)

        # lock everything we're going to update in one call so mysql can ensure that the locking is ordered
        key_currency_accounts = (
            session.query(KeyCurrencyAccount)
            .filter(
                KeyCurrencyAccount.key_uuid.in_(key_uuids_to_lock),
                KeyCurrencyAccount.currency == Currency.BTC,
            )
            .populate_existing()
            .with_for_update()
            .all()
        )
        key_uuid_to_key_currency_account = {kca.key_uuid: kca for kca in key_currency_accounts}
        if should_dest_be_admin and dest_key is not None:
            dest_key_currency_account = key_uuid_to_key_currency_account[dest_key.key_uuid]
            if dest_key_currency_account.account_uuid != ADMIN_UUID:
                raise RuntimeError("Dest account not admin")
            dest_key_currency_account.pending_admin_deposits += 1

        remaining_currency_account = key_uuid_to_key_currency_account[remainder_key.key_uuid]
        assert remaining_currency_account.account_uuid == ADMIN_UUID
        remaining_currency_account.pending_admin_deposits += 1

        for input_address, address_amount in input_address_to_amount.items():
            key_currency = key_uuid_to_key_currency_account[address_to_key_uuid[input_address]]
            assert key_currency.available_balance is not None
            key_currency.available_balance -= address_amount

        session.commit()
        return pending_blockchain_transaction.uuid, tx_params_any_pb

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
        tx_params_pb = BitcoinTxParams()
        if not tx_params_any_pb.Unpack(tx_params_pb):
            raise RuntimeError("Unable to unpack any pb")
        btc_vouts_and_keys = (
            session.query(BTCVout, Key)
            .filter(
                tuple_(BTCVout.txid, BTCVout.voutindex).in_(
                    [(HexBytes(src.txid), src.vout) for src in tx_params_pb.sources]
                ),
                BlockchainAddressKey.address == BTCVout.address,
                BlockchainAddressKey.blockchain == Blockchain.BTC,
                Key.key_uuid == BlockchainAddressKey.key_uuid,
            )
            .all()
        )
        txid_and_vout_to_src_address: Dict[Tuple[HexBytes, int], str] = {}
        address_to_private_key: Dict[str, CBitcoinSecret] = {}
        for btc_vout, key in btc_vouts_and_keys:
            private_key_bn = key.private_key
            assert isinstance(private_key_bn, petlib.bn.Bn)
            private_key = CBitcoinSecret.from_secret_bytes(private_key_bn.binary().rjust(32, b"\0"))
            bitcoin_address = key.get_address(Blockchain.BTC)
            address_to_private_key[bitcoin_address] = private_key
            txid_and_vout_to_src_address[(HexBytes(btc_vout.txid), btc_vout.voutindex)] = bitcoin_address
        tx_ins: List[CMutableTxIn] = []
        for source in tx_params_pb.sources:
            txid = source.txid
            vout = source.vout
            txin = CMutableTxIn(COutPoint(txid, vout))
            tx_ins.append(txin)
        tx_outs: List[CMutableTxOut] = []
        for destination in tx_params_pb.destinations:
            value_dec = Decimal(destination.value) * Decimal(COIN)
            value = int(value_dec)
            if Decimal(value) != value_dec:
                raise RuntimeError("Loss of precision")
            tx_outs.append(CMutableTxOut(value, CBitcoinAddress(destination.toAddress).to_scriptPubKey()))
        tx = CMutableTransaction(tx_ins, tx_outs)
        for i, source in enumerate(tx_params_pb.sources):
            from_address = txid_and_vout_to_src_address[(HexBytes(source.txid), source.vout)]
            txin_script_pub_key = CBitcoinAddress(from_address).to_scriptPubKey()
            sighash = SignatureHash(txin_script_pub_key, tx, i, SIGHASH_ALL)
            seckey = address_to_private_key[from_address]
            sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
            txin = tx.vin[i]
            txin.scriptSig = CScript([sig, seckey.pub])
            VerifyScript(txin.scriptSig, txin_script_pub_key, tx, i, (SCRIPT_VERIFY_P2SH,))
        signed_transaction = HexBytes(tx.serialize())
        blockchain_withdrawal.signed_tx = signed_transaction
        return self._create_withdrawal_transaction_identifier(tx.GetTxid())

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
        tx_params_pb = BitcoinTxParams()
        if not tx_params_any_pb.Unpack(tx_params_pb):
            raise RuntimeError("Unable to unpack any pb")
        tx = CMutableTransaction.deserialize(signed_transaction)
        for i, source in enumerate(tx_params_pb.sources):
            txid = source.txid
            vout = source.vout
            txin = tx.vin[i]
            if not txin.prevout == COutPoint(txid, vout):
                raise ValueError(
                    f"Signed transaction has incorrect COutPoint at index {i}:"
                    f"{txin.prevout} != {COutPoint(txid, vout)}"
                )
            from_btc_vout = (
                session.query(BTCVout)
                .filter(
                    BTCVout.txid == HexBytes(txid),
                    BTCVout.voutindex == vout,
                )
                .one()
            )
            from_address = from_btc_vout.address
            txin_script_pub_key = CBitcoinAddress(from_address).to_scriptPubKey()
            VerifyScript(txin.scriptSig, txin_script_pub_key, tx, i, (SCRIPT_VERIFY_P2SH,))
        for i, destination in enumerate(tx_params_pb.destinations):
            txout = tx.vout[i]
            value_dec = Decimal(destination.value) * Decimal(COIN)
            value = int(value_dec)
            if Decimal(value) != value_dec:
                raise RuntimeError("Loss of precision")
            expected_txout = CMutableTxOut(value, CBitcoinAddress(destination.toAddress).to_scriptPubKey())
            if not txout == expected_txout:
                raise ValueError(f"Signed transaction has incorrect txout[{i}]: {txout} != {expected_txout}")

        blockchain_withdrawal.signed_tx = signed_transaction
        return self._create_withdrawal_transaction_identifier(tx.GetTxid())

    def get_cold_transactions_awaiting_signature(self) -> Sequence[Any]:
        raise NotImplementedError()
