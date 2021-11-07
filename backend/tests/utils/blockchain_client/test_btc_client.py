import logging
import time
import unittest
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from unittest.mock import patch

import grpc
import petlib.bn
import petlib.ec
from bitcoin.core import (
    COIN,
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
)
from bitcoin.core.script import SIGHASH_ALL, CScript, SignatureHash
from bitcoin.core.scripteval import SCRIPT_VERIFY_P2SH, VerifyScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from common.constants import Blockchain, Currency
from hexbytes.main import HexBytes
from protobufs.account_pb2 import AccountType
from protobufs.bitcoin_pb2 import BitcoinTransactionDestination, BitcoinTxParams
from protobufs.institution.account_pb2 import (
    KeyType,
    TransactionStatus,
    TransactionType,
)
from sqlalchemy import tuple_
from sqlalchemy.orm.exc import NoResultFound

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.blockchain_address_key import BlockchainAddressKey
from backend.sql.blockchain_transaction import BlockchainTransaction
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.btc_vout import BTCVout
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.sql.key_currency_account import KeyCurrencyAccount
from backend.sql.key_currency_block import KeyCurrencyBlock
from backend.sql.transaction import Transaction
from backend.utils.blockchain_client.btc import BTCClient
from tests.base import BaseBackendTestCase
from tests.fixtures import (
    BTC_AMOUNT_1,
    BTC_AMOUNT_2,
    MOCK_USER_UUID,
    BtcFixturesContainer,
    wait_for_bitcoin_tx,
)

TX_FEE_RATE = Decimal("0.00019")
LOGGER = logging.getLogger(__name__)


def mock_get_tx_fee_rate(self: BTCClient) -> Decimal:  # pylint: disable=unused-argument
    return TX_FEE_RATE


@patch.object(BTCClient, "_get_tx_fee_rate", mock_get_tx_fee_rate)
class TestBTCClient(BaseBackendTestCase):
    backend: Backend
    channel: grpc.Channel
    start_block: int
    num_confirmations: int
    fixture_container: BtcFixturesContainer

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        start_block = cls.backend.btc_client.start_block_number
        cls.start_block = start_block
        cls.num_confirmations = cls.backend.btc_client._num_confirmations  # pylint: disable=protected-access
        num_tests = len(list(filter(lambda x: x.startswith("test_"), dir(cls))))
        cls.fixture_container = BtcFixturesContainer(num_tests)

    def setUp(self) -> None:
        super().setUp()
        self.btc_fixture = self.fixture_container()
        tx1_block_number = self.btc_fixture.tx_1.blockheight
        self.tx1_block_number = tx1_block_number
        tx2_block_number = self.btc_fixture.tx_2.blockheight
        self.tx2_block_number = tx2_block_number
        with self.backend.sessionmaker() as session:
            account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.BTC,
                account_type=AccountType.DEPOSIT_ACCOUNT,
            )
            session.add(account)
            session.commit()
            self.account_uuid = account.uuid
        private_key_bn = petlib.bn.Bn.from_binary(self.btc_fixture.private_key)
        self.key_uuid = self.backend.key_client.import_hot_key(private_key_bn)
        with self.backend.sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == self.key_uuid).one()
            self.address = key.get_address(Blockchain.BTC)
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=self.key_uuid, account_uuid=self.account_uuid
        )

        for block_number in range(self.start_block, self.tx2_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)

    def test_deposits(self) -> None:
        # tx1 should be confirmed, and tx2 should be pending.
        with self.backend.sessionmaker() as session:
            account = session.query(Account).filter(Account.uuid == self.account_uuid).one()
            self.assertEqual(account.available_amount, BTC_AMOUNT_1)
            self.assertEqual(account.pending_amount, BTC_AMOUNT_2)
            blockchain_transaction_1, transaction_1 = (
                session.query(BlockchainTransaction, Transaction)
                .filter(
                    Transaction.account_uuid == self.account_uuid,
                    Transaction.status == TransactionStatus.COMPLETED,
                    BlockchainTransaction.transaction_uuid == Transaction.uuid,
                )
                .one()
            )
            self.assertEqual(transaction_1.amount, BTC_AMOUNT_1)
            self.assertEqual(transaction_1.transaction_type, TransactionType.DEPOSIT)
            self.assertEqual(blockchain_transaction_1.block_number, self.tx1_block_number)

            blockchain_transaction_2, transaction_2 = (
                session.query(BlockchainTransaction, Transaction)
                .filter(
                    Transaction.account_uuid == self.account_uuid,
                    Transaction.status == TransactionStatus.PENDING,
                    BlockchainTransaction.transaction_uuid == Transaction.uuid,
                )
                .one()
            )
            self.assertEqual(transaction_2.amount, BTC_AMOUNT_2)
            self.assertEqual(transaction_2.transaction_type, TransactionType.DEPOSIT)
            self.assertEqual(blockchain_transaction_2.block_number, self.tx2_block_number)
        tx2_confirmation_block_number = self.tx2_block_number + self.backend.btc_client.num_confirmations - 1
        self._wait_for_block(tx2_confirmation_block_number)
        for block_number in range(self.tx2_block_number + 1, tx2_confirmation_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
        with self.backend.sessionmaker() as session:
            account = session.query(Account).filter(Account.uuid == self.account_uuid).one()
            self.assertEqual(account.available_amount, BTC_AMOUNT_1 + BTC_AMOUNT_2)
            self.assertEqual(account.pending_amount, Decimal(0))
            self.assertEqual(
                session.query(Transaction)
                .filter(
                    Transaction.account_uuid == self.account_uuid,
                    Transaction.status == TransactionStatus.COMPLETED,
                )
                .count(),
                2,
            )

    def test_get_available_and_pending_balance(self) -> None:
        with self.backend.sessionmaker() as session:
            account = session.query(Account).filter(Account.uuid == self.account_uuid).one()
            amount = account.pending_amount + account.available_amount
            self.assertEqual(amount, BTC_AMOUNT_1 + BTC_AMOUNT_2)

    def test_get_cumulative_deposits(self) -> None:
        self.assertEqual(
            self.backend.btc_client.get_cumulative_deposits(
                self.key_uuid,
                Currency.BTC,
                from_block_number=self.start_block + 1,
                to_block_number=self.tx1_block_number - 1,
            ),
            Decimal(0),
        )
        for block_number in range(self.tx1_block_number, self.tx2_block_number):
            self.assertEqual(
                self.backend.btc_client.get_cumulative_deposits(
                    self.key_uuid, Currency.BTC, from_block_number=self.start_block + 1, to_block_number=block_number
                ),
                BTC_AMOUNT_1,
            )

        self.assertEqual(
            self.backend.btc_client.get_cumulative_deposits(
                self.key_uuid,
                Currency.BTC,
                from_block_number=self.start_block + 1,
                to_block_number=self.tx2_block_number,
            ),
            BTC_AMOUNT_1 + BTC_AMOUNT_2,
        )

    def test_key_approximate_bal(self) -> None:
        with self.backend.sessionmaker() as session:
            key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )

            expected_bal = BTC_AMOUNT_1 + BTC_AMOUNT_2
            self.assertEqual(key_currency.available_balance, expected_bal)

    def test_create_pending_transaction(self) -> None:
        amount = Decimal("0.23")
        with self.backend.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            destination_address = str(proxy.getnewaddress())
        with self.backend.sessionmaker() as session:
            pending_tx_id, pending_tx_params_any_pb = self.backend.btc_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.BTC,
                destination_address=destination_address,
                key_type=KeyType.HOT,
                should_dest_be_admin=False,
            )
            session.commit()

        with self.backend.sessionmaker() as session:
            pending_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            pending_tx_pb = BitcoinTxParams()
            self.assertTrue(pending_tx_params_any_pb.Unpack(pending_tx_pb))
            self.assertEqual(pending_tx.tx_params, pending_tx_params_any_pb)
            self.assertEqual(pending_tx.blockchain, Blockchain.BTC)

            self.assertIsNone(pending_tx.signed_tx)
            self.assertIsNone(pending_tx.txn_hash)
            self.assertIsNone(pending_tx.last_broadcast_at)
            self.assertIsNone(pending_tx.block_number)

            source_key, source_key_currency_account = (
                session.query(Key, KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                    Key.key_uuid == KeyCurrencyAccount.key_uuid,
                )
                .one()
            )
            change_destination: Optional[BitcoinTransactionDestination] = None
            wanted_destination: Optional[BitcoinTransactionDestination] = None
            for destination in pending_tx_pb.destinations:
                if destination.toAddress == destination_address:
                    wanted_destination = destination
                else:
                    change_destination = destination
            assert change_destination is not None, "change address not found"
            assert wanted_destination is not None, "wanged destination is None"

            spent_btc_vouts = (
                session.query(BTCVout)
                .filter(
                    tuple_(BTCVout.txid, BTCVout.voutindex).in_(
                        [(HexBytes(source.txid), source.vout) for source in pending_tx_pb.sources]
                    )
                )
                .all()
            )
            self.assertEqual(len(spent_btc_vouts), 2)
            self.assertEqual(spent_btc_vouts[0].address, source_key.get_address(Blockchain.BTC))
            self.assertTrue(spent_btc_vouts[0].spent)
            self.assertTrue(spent_btc_vouts[1].spent)
            self.assertNotEqual(change_destination.toAddress, self.btc_fixture.address)
            self.assertEqual(
                wanted_destination,
                BitcoinTransactionDestination(
                    value=str(amount.normalize()),
                    toAddress=destination_address,
                ),
            )
            self.assertEqual(
                source_key_currency_account.available_balance,
                0,
            )
            change_key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    BlockchainAddressKey.address == change_destination.toAddress,
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                    BlockchainAddressKey.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(
                change_key_currency_account.pending_admin_deposits,
                1,
            )

    def test_create_pending_transaction_admin(self) -> None:
        amount = Decimal("0.23")
        admin_key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            admin_key = session.query(Key).filter(Key.key_uuid == admin_key_uuid).one()
            destination_address = admin_key.get_address(Blockchain.BTC)
            pending_tx_id, pending_tx_params_any_pb = self.backend.btc_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.BTC,
                destination_address=destination_address,
                key_type=KeyType.HOT,
                should_dest_be_admin=True,
            )
            session.commit()
        with self.backend.sessionmaker() as session:
            pending_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            pending_tx_pb = BitcoinTxParams()
            self.assertTrue(pending_tx_params_any_pb.Unpack(pending_tx_pb))
            self.assertEqual(pending_tx.tx_params, pending_tx_params_any_pb)
            self.assertEqual(pending_tx.blockchain, Blockchain.BTC)

            self.assertIsNone(pending_tx.signed_tx)
            self.assertIsNone(pending_tx.txn_hash)
            self.assertIsNone(pending_tx.last_broadcast_at)
            self.assertIsNone(pending_tx.block_number)

            source_key, source_key_currency_account = (
                session.query(Key, KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                    Key.key_uuid == KeyCurrencyAccount.key_uuid,
                )
                .one()
            )
            change_destination: Optional[BitcoinTransactionDestination] = None
            wanted_destination: Optional[BitcoinTransactionDestination] = None
            for destination in pending_tx_pb.destinations:
                if destination.toAddress == destination_address:
                    wanted_destination = destination
                else:
                    change_destination = destination
            assert change_destination is not None, "change address not found"
            assert wanted_destination is not None, "wanged destination is None"

            spent_btc_vouts = (
                session.query(BTCVout)
                .filter(
                    tuple_(BTCVout.txid, BTCVout.voutindex).in_(
                        [(HexBytes(source.txid), source.vout) for source in pending_tx_pb.sources]
                    )
                )
                .all()
            )
            self.assertEqual(len(spent_btc_vouts), 2)
            self.assertEqual(spent_btc_vouts[0].address, source_key.get_address(Blockchain.BTC))
            self.assertTrue(spent_btc_vouts[0].spent)
            self.assertTrue(spent_btc_vouts[1].spent)
            self.assertNotEqual(change_destination.toAddress, self.btc_fixture.address)
            self.assertEqual(
                wanted_destination,
                BitcoinTransactionDestination(
                    value=str(amount.normalize()),
                    toAddress=destination_address,
                ),
            )
            self.assertEqual(
                source_key_currency_account.available_balance,
                0,
            )
            change_key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    BlockchainAddressKey.address == change_destination.toAddress,
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                    BlockchainAddressKey.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(
                change_key_currency_account.pending_admin_deposits,
                1,
            )
            wanted_key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    BlockchainAddressKey.address == wanted_destination.toAddress,
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                    BlockchainAddressKey.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(
                wanted_key_currency_account.pending_admin_deposits,
                1,
            )
            self.assertNotEqual(wanted_destination.toAddress, change_destination.toAddress)

    def _wait_for_block(self, block_number: int, timeout_seconds: int = 20) -> None:
        for i in range(timeout_seconds):
            if self.backend.btc_client.get_latest_block_number_from_chain() >= block_number:
                break
            if i < timeout_seconds - 1:
                time.sleep(1)
                continue
            raise RuntimeError("Timeout")

    def test_create_pending_transaction_admin_fails(self) -> None:
        amount = Decimal("0.013")
        new_key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            new_key = session.query(Key).filter(Key.key_uuid == new_key_uuid).one()
            destination_address = new_key.get_address(Blockchain.BTC)
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=new_key_uuid, account_uuid=self.account_uuid
        )
        with self.assertRaises(RuntimeError):
            with self.backend.sessionmaker() as session:
                self.backend.btc_client.create_pending_transaction(
                    session,
                    amount=amount,
                    currency=Currency.BTC,
                    destination_address=destination_address,
                    key_type=KeyType.HOT,
                    should_dest_be_admin=True,
                )
                session.commit()

    def test_queue_hot_transactions(self) -> None:
        amount = Decimal("0.23")
        with self.backend.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            destination_address = str(proxy.getnewaddress())
        with self.backend.sessionmaker() as session:
            pending_tx_id, ignored_pending_tx_params_any_pb = self.backend.btc_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.BTC,
                destination_address=destination_address,
                key_type=KeyType.HOT,
                should_dest_be_admin=False,
            )
            session.commit()
        with self.backend.sessionmaker() as session:
            self.backend.btc_client.queue_hot_transaction(session, pending_tx_id)
            session.commit()
        with self.backend.sessionmaker() as session:
            pending_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            self.assertIsNotNone(pending_tx.signed_tx)
        with self.assertRaises(NoResultFound):
            with self.backend.sessionmaker() as session:
                self.backend.btc_client.queue_hot_transaction(session, pending_tx_id)  # can't queue twice
                session.commit()

    def test_queue_cold_transaction(self) -> None:
        amount = Decimal("0.23")
        with self.backend.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            destination_address = str(proxy.getnewaddress())
        with self.backend.sessionmaker() as session:
            pending_tx_id, pending_tx_params_any_pb = self.backend.btc_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.BTC,
                destination_address=destination_address,
                key_type=KeyType.HOT,
                should_dest_be_admin=False,
            )
            session.commit()
        tx_params_pb = BitcoinTxParams()
        self.assertTrue(pending_tx_params_any_pb.Unpack(tx_params_pb))

        with self.backend.sessionmaker() as session:
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

        with self.backend.sessionmaker() as session:
            blockchain_transaction_identifier = self.backend.btc_client.queue_cold_transaction(
                session, pending_tx_id, signed_transaction
            )
            self.assertEqual(
                self.backend.btc_client._create_withdrawal_transaction_identifier(  # pylint: disable=protected-access
                    tx.GetTxid()
                ),
                blockchain_transaction_identifier,
            )
            session.commit()
        with self.backend.sessionmaker() as session:
            pending_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            self.assertIsNotNone(pending_tx.signed_tx)
        with self.assertRaises(NoResultFound):
            with self.backend.sessionmaker() as session:
                self.backend.btc_client.queue_hot_transaction(session, pending_tx_id)  # can't queue twice
                session.commit()

    def test_broadcast_reconcile_prune(self) -> None:
        admin_key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            admin_key = session.query(Key).filter(Key.key_uuid == admin_key_uuid).one()
            destination_address = admin_key.get_address(Blockchain.BTC)
            amount = Decimal("0.23")
            pending_tx_id, ignored_pending_tx_any_pb = self.backend.btc_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.BTC,
                destination_address=destination_address,
                key_type=KeyType.HOT,
                should_dest_be_admin=True,
            )
            session.commit()
        with self.backend.sessionmaker() as session:
            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == admin_key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(admin_key_currency.pending_admin_deposits, 1)
        with self.backend.sessionmaker() as session:
            blockchain_transaction_identifier = self.backend.btc_client.queue_hot_transaction(session, pending_tx_id)
            session.commit()
        self._wait_for_block(self.tx2_block_number + 1)

        # broadcast the transaction onto the chain
        self.backend.blockchain_client.process_block(Blockchain.BTC, self.tx2_block_number + 1)
        self.backend.blockchain_client.process_block(Blockchain.BTC, self.tx2_block_number + 1)
        with self.backend.sessionmaker() as session:
            pending_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            txn_hash = pending_tx.txn_hash
            tx_params_any_pb = pending_tx.tx_params
            tx_params = BitcoinTxParams()
            self.assertTrue(tx_params_any_pb.Unpack(tx_params))

            admin_dest: Optional[BitcoinTransactionDestination] = None
            change_dest: Optional[BitcoinTransactionDestination] = None
            for dest in tx_params.destinations:
                if dest.toAddress == destination_address:
                    admin_dest = dest
                else:
                    change_dest = dest

            assert admin_dest is not None
            assert change_dest is not None
            self.assertNotEqual(change_dest.toAddress, admin_dest.toAddress)

            # there should only be one key since both deposits went to the same place
            key = (
                session.query(Key)
                .filter(
                    tuple_(BTCVout.txid, BTCVout.voutindex).in_(
                        [(HexBytes(source.txid), source.vout) for source in tx_params.sources]
                    ),
                    BTCVout.address == BlockchainAddressKey.address,
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                    BlockchainAddressKey.key_uuid == Key.key_uuid,
                )
                .one()
            )
            key_uuid = key.key_uuid

            # the BTCVout should be marked as spent but should not yet have a spent block number
            btc_vouts = (
                session.query(BTCVout)
                .filter(
                    tuple_(BTCVout.txid, BTCVout.voutindex).in_(
                        [(HexBytes(source.txid), source.vout) for source in tx_params.sources]
                    ),
                )
                .all()
            )
            self.assertEqual(len(btc_vouts), 2)
            self.assertTrue(btc_vouts[0].spent)
            self.assertTrue(btc_vouts[1].spent)
            self.assertIsNone(btc_vouts[0].spent_block_number)
            self.assertIsNone(btc_vouts[1].spent_block_number)

            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == admin_key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(admin_key_currency.pending_admin_deposits, 1)

        # it SHOULD be included within the next block
        with self.backend.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            tx_receipt = wait_for_bitcoin_tx(proxy, txn_hash)
        self.assertEqual(
            self.backend.btc_client._create_withdrawal_transaction_identifier(  # pylint: disable=protected-access
                txn_hash
            ),
            blockchain_transaction_identifier,
        )
        reconcile_block_number = tx_receipt.blockheight
        prune_block_number = reconcile_block_number + self.backend.btc_client.num_confirmations - 1
        for block_number in range(self.tx2_block_number + 2, reconcile_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
        with self.backend.sessionmaker() as session:
            key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(key_currency.available_balance, Decimal("0"))

            # the btc vout should have the block number set now
            btc_vouts = (
                session.query(BTCVout)
                .filter(
                    tuple_(BTCVout.txid, BTCVout.voutindex).in_(
                        [(HexBytes(source.txid), source.vout) for source in tx_params.sources]
                    ),
                )
                .all()
            )
            self.assertEqual(btc_vouts[0].spent_block_number, reconcile_block_number)
            self.assertEqual(btc_vouts[1].spent_block_number, reconcile_block_number)

            # the new admin account should have the remaining balance
            change_kca = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == BlockchainAddressKey.key_uuid,
                    BlockchainAddressKey.address == change_dest.toAddress,
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )

            self.assertEqual(change_kca.available_balance, Decimal(change_dest.value))
            self.assertEqual(change_kca.pending_admin_deposits, 1)

            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == admin_key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(admin_key_currency.pending_admin_deposits, 1)

            pending_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            self.assertEqual(pending_tx.block_number, reconcile_block_number)
        self._wait_for_block(prune_block_number)
        for block_number in range(reconcile_block_number + 1, prune_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
        with self.backend.sessionmaker() as session:
            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.currency == Currency.BTC,
                    KeyCurrencyAccount.key_uuid == key_uuid,
                )
                .one()
            )
            # the deposits are no longer pending
            self.assertEqual(admin_key_currency.pending_admin_deposits, 0)

            change_kca = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == BlockchainAddressKey.key_uuid,
                    BlockchainAddressKey.address == admin_dest.toAddress,
                    BlockchainAddressKey.blockchain == Blockchain.BTC,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            # the deposits are no longer pending
            self.assertEqual(admin_key_currency.pending_admin_deposits, 0)
            self.assertEqual(change_kca.pending_admin_deposits, 0)

            # no more pending transactions; they've been deleted
            self.assertEqual(
                session.query(BlockchainWithdrawal)
                .filter(BlockchainWithdrawal.pending_admin_deposits_reconciled.is_(False))
                .count(),
                0,
            )

    def test_void_transaction(self) -> None:
        admin_key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            admin_key = session.query(Key).filter(Key.key_uuid == admin_key_uuid).one()
            destination_address = admin_key.get_address(Blockchain.BTC)
            amount = Decimal("0.23")
            pending_tx_id, ignored_pending_tx_any_pb = self.backend.btc_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.BTC,
                destination_address=destination_address,
                key_type=KeyType.HOT,
                should_dest_be_admin=True,
            )
            session.commit()

        with self.backend.sessionmaker() as session:
            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == admin_key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(admin_key_currency.pending_admin_deposits, 1)

        self._wait_for_block(self.tx2_block_number + 1)
        # processing the next block will cause the transaction to be voided
        self.backend.blockchain_client.process_block(Blockchain.BTC, self.tx2_block_number + 1)
        self.backend.blockchain_client.process_block(Blockchain.BTC, self.tx2_block_number + 1)
        with self.backend.sessionmaker() as session:
            pending_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one_or_none()
            )
            self.assertIsNone(pending_tx, "voided tx should be deleted")

            btc_vouts = session.query(BTCVout).filter(BTCVout.address == self.btc_fixture.address).all()
            for btc_vout in btc_vouts:
                self.assertFalse(btc_vout.spent, "voided transaction should not have spent btc vout")

            key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )

            # transaction amount should be returned
            self.assertEqual(key_currency.available_balance, BTC_AMOUNT_1 + BTC_AMOUNT_2)

            # no pending deposits so all key currencies should have 0 pending admin deposits
            key_currencies = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .all()
            )
            for key_currency in key_currencies:
                self.assertEqual(key_currency.pending_admin_deposits, 0)


class TestBTCInitialBalance(BaseBackendTestCase):
    # Using a separate class since we don't want the same setUp method
    # specifically, we do NOT want to manually track the key, since thatis
    # what we are testing
    backend: Backend
    channel: grpc.Channel
    start_block: int
    num_confirmations: int
    fixture_container: BtcFixturesContainer

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        start_block = cls.backend.btc_client.start_block_number
        cls.start_block = start_block
        cls.num_confirmations = cls.backend.btc_client._num_confirmations  # pylint: disable=protected-access
        num_tests = len(list(filter(lambda x: x.startswith("test_"), dir(cls))))
        cls.fixture_container = BtcFixturesContainer(num_tests)

    def setUp(self) -> None:
        super().setUp()
        self.btc_fixture = self.fixture_container()
        self.tx1_block_number = self.btc_fixture.tx_1.blockheight
        self.tx2_block_number = self.btc_fixture.tx_2.blockheight
        for block_number in range(self.start_block, self.tx2_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
        with self.backend.sessionmaker() as session:
            account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.BTC,
                account_type=AccountType.DEPOSIT_ACCOUNT,
            )
            session.add(account)
            session.commit()
            self.account_uuid = account.uuid

    def _wait_for_block(self, block_number: int, timeout_seconds: int = 20) -> None:
        for i in range(timeout_seconds):
            if self.backend.btc_client.get_latest_block_number_from_chain() >= block_number:
                break
            if i < timeout_seconds - 1:
                time.sleep(1)
                continue
            raise RuntimeError("Timeout")

    def test_late_import(self) -> None:
        private_key_bn = petlib.bn.Bn.from_binary(self.btc_fixture.private_key)
        key_uuid = self.backend.key_client.import_hot_key(private_key_bn)
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=key_uuid,
            account_uuid=self.account_uuid,
        )
        self._wait_for_block(self.tx2_block_number + 1)
        self.backend.blockchain_client.process_block(Blockchain.BTC, self.tx2_block_number + 1)
        with self.backend.sessionmaker() as session:
            key_currency_block = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.key_uuid == key_uuid,
                    KeyCurrencyBlock.currency == Currency.BTC,
                )
                .one()
            )
            key_account_commitment, key_currency_account = (
                session.query(
                    KeyAccountCommitment,
                    KeyCurrencyAccount,
                )
                .filter(
                    KeyAccountCommitment.key_uuid == key_uuid,
                    KeyAccountCommitment.account_uuid == self.account_uuid,
                    KeyAccountCommitment.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(key_currency_block.block_number, key_currency_account.initial_balance_block_number)
            self.assertEqual(key_currency_block.block_number, key_account_commitment.block_number)
            self.assertEqual(key_currency_account.initial_balance, BTC_AMOUNT_1 + BTC_AMOUNT_2)
            self.assertEqual(key_currency_account.available_balance, BTC_AMOUNT_1 + BTC_AMOUNT_2)

    def test_late_import_with_withdrawal(self) -> None:
        withdraw_amount = Decimal("0.02")
        tx1id = self.btc_fixture.tx_1.tx.GetTxid()
        tx1voutindex: Optional[int] = None
        for i, vout in enumerate(self.btc_fixture.tx_1.tx.vout):
            if str(CBitcoinAddress.from_scriptPubKey(vout.scriptPubKey)) == self.btc_fixture.address:
                tx1voutindex = i
        self.assertIsNotNone(tx1voutindex, "vout not found")
        tx_ins = [CMutableTxIn(COutPoint(tx1id, tx1voutindex))]
        tx_outs = [
            CMutableTxOut(int(withdraw_amount * COIN), CBitcoinAddress(self.btc_fixture.address).to_scriptPubKey())
        ]
        tx = CMutableTransaction(tx_ins, tx_outs)
        txin_script_pub_key = CBitcoinAddress(self.btc_fixture.address).to_scriptPubKey()
        seckey = CBitcoinSecret.from_secret_bytes(self.btc_fixture.private_key)
        sighash = SignatureHash(txin_script_pub_key, tx, 0, SIGHASH_ALL)
        sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
        tx.vin[0].scriptSig = CScript([sig, seckey.pub])
        VerifyScript(tx.vin[0].scriptSig, txin_script_pub_key, tx, 0, (SCRIPT_VERIFY_P2SH,))
        tx3id = self.backend.btc_client._broadcast_transaction(tx.serialize())  # pylint: disable=protected-access
        with self.backend.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            tx3receipt = wait_for_bitcoin_tx(proxy, tx3id)
        tx3_block_number = tx3receipt.blockheight

        self._wait_for_block(tx3_block_number)
        for block_number in range(self.tx2_block_number + 1, tx3_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.BTC, block_number)
        private_key_bn = petlib.bn.Bn.from_binary(self.btc_fixture.private_key)
        key_uuid = self.backend.key_client.import_hot_key(private_key_bn)
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=key_uuid,
            account_uuid=self.account_uuid,
        )
        self._wait_for_block(tx3_block_number + 1)
        self.backend.blockchain_client.process_block(Blockchain.BTC, tx3_block_number + 1)

        with self.backend.sessionmaker() as session:
            key_currency_block = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.key_uuid == key_uuid,
                    KeyCurrencyBlock.currency == Currency.BTC,
                )
                .one()
            )
            key_account_commitment, key_currency_account = (
                session.query(
                    KeyAccountCommitment,
                    KeyCurrencyAccount,
                )
                .filter(
                    KeyAccountCommitment.key_uuid == key_uuid,
                    KeyAccountCommitment.account_uuid == self.account_uuid,
                    KeyAccountCommitment.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(key_currency_block.block_number, key_currency_account.initial_balance_block_number)
            self.assertEqual(key_currency_block.block_number, key_account_commitment.block_number)
            # we are simply sending bitcoin to ourselves and burning the rest
            self.assertEqual(key_currency_account.initial_balance, BTC_AMOUNT_2 + withdraw_amount)
            self.assertEqual(key_currency_account.available_balance, BTC_AMOUNT_2 + withdraw_amount)


if __name__ == "__main__":
    unittest.main()
