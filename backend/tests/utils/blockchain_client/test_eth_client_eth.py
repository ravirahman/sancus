import unittest
from decimal import Decimal
from typing import cast
from unittest.mock import patch

import grpc
import petlib.bn
import web3
from common.constants import ADMIN_UUID, Blockchain, Currency
from eth_account.account import Account as ETHAccount
from protobufs.account_pb2 import AccountType
from protobufs.eth_pb2 import EthereumTxParams
from protobufs.institution.account_pb2 import (
    KeyType,
    TransactionStatus,
    TransactionType,
)
from sqlalchemy.orm.exc import NoResultFound
from web3.types import TxReceipt

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.blockchain_address_key import BlockchainAddressKey
from backend.sql.blockchain_transaction import BlockchainTransaction
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.sql.key_currency_account import KeyCurrencyAccount
from backend.sql.key_currency_block import KeyCurrencyBlock
from backend.sql.transaction import Transaction
from backend.utils.blockchain_client.eth import ETHClient
from tests.base import BaseBackendTestCase
from tests.fixtures import (
    ETH1_AMOUNT,
    ETH2_AMOUNT,
    MAIN_ETH_ACCOUNT,
    MOCK_USER_UUID,
    EthFixturesContainer,
    wait_for_eth_block,
)

GAS_PRICE_WEI = 17


def mock_get_eth_gas_price(self: ETHClient) -> int:  # pylint: disable=unused-argument
    return GAS_PRICE_WEI


@patch.object(ETHClient, "_get_gas_price", mock_get_eth_gas_price)
class TestETHClientETH(BaseBackendTestCase):
    backend: Backend
    w3: web3.Web3
    channel: grpc.Channel
    start_block: int
    fixture_container: EthFixturesContainer

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.w3 = cls.backend.eth_client._w3  # pylint: disable=protected-access
        start_block = cls.backend.eth_client.start_block_number
        cls.start_block = start_block
        num_tests = len(list(filter(lambda x: x.startswith("test_"), dir(cls))))
        cls.fixture_container = EthFixturesContainer(cls.backend.eth_client, num_tests)

    def setUp(self) -> None:
        super().setUp()
        self.eth_fixture = self.fixture_container()
        with self.backend.sessionmaker() as session:
            # add an ethereum account
            eth_account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.ETH,
                account_type=AccountType.DEPOSIT_ACCOUNT,
            )
            session.add(eth_account)
            session.commit()
            self.eth_account_uuid = eth_account.uuid
            private_key_bn = petlib.bn.Bn.from_binary(self.eth_fixture.private_key)

        # track the keys
        self.key_uuid = self.backend.key_client.import_hot_key(
            private_key_bn,
            self.w3.eth.get_transaction_count(self.eth_fixture.address),
        )
        with self.backend.sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == self.key_uuid).one()
            self.assertEqual(key.get_address(Blockchain.ETH), self.eth_fixture.address)
            # assign the keys
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=self.key_uuid, account_uuid=self.eth_account_uuid
        )
        # process the blocks
        for block_number in range(self.start_block, self.eth_fixture.eth2_tx_receipt.blockNumber + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)

    def test_deposits(self) -> None:
        # as of right now, tx1 should be pending or confirmed, and tx2 should be pending
        tx1_confirmation_block_number = (
            self.eth_fixture.eth1_tx_receipt.blockNumber + self.backend.eth_client.num_confirmations - 1
        )
        wait_for_eth_block(self.backend.eth_client, tx1_confirmation_block_number)
        if self.eth_fixture.eth2_tx_receipt.blockNumber + 1 < tx1_confirmation_block_number:
            for block_number in range(self.eth_fixture.eth2_tx_receipt.blockNumber + 1, tx1_confirmation_block_number):
                self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
                self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
        # tx1 should be confirmed, and tx2 should be pending.
        with self.backend.sessionmaker() as session:
            account = session.query(Account).filter(Account.uuid == self.eth_account_uuid).one()
            self.assertEqual(account.available_amount, ETH1_AMOUNT)
            self.assertEqual(account.pending_amount, ETH2_AMOUNT)
            blockchain_transaction_1, transaction_1 = (
                session.query(BlockchainTransaction, Transaction)
                .filter(
                    Transaction.account_uuid == self.eth_account_uuid,
                    Transaction.status == TransactionStatus.COMPLETED,
                    BlockchainTransaction.transaction_uuid == Transaction.uuid,
                )
                .one()
            )
            self.assertEqual(transaction_1.amount, ETH1_AMOUNT)
            self.assertEqual(transaction_1.transaction_type, TransactionType.DEPOSIT)
            self.assertEqual(blockchain_transaction_1.block_number, self.eth_fixture.eth1_tx_receipt.blockNumber)

            blockchain_transaction_2, transaction_2 = (
                session.query(BlockchainTransaction, Transaction)
                .filter(
                    Transaction.account_uuid == self.eth_account_uuid,
                    Transaction.status == TransactionStatus.PENDING,
                    BlockchainTransaction.transaction_uuid == Transaction.uuid,
                )
                .one()
            )
            self.assertEqual(transaction_2.amount, ETH2_AMOUNT)
            self.assertEqual(transaction_2.transaction_type, TransactionType.DEPOSIT)
            self.assertEqual(blockchain_transaction_2.block_number, self.eth_fixture.eth2_tx_receipt.blockNumber)
        tx2_confirmation_block_number = (
            self.eth_fixture.eth2_tx_receipt.blockNumber + self.backend.eth_client.num_confirmations - 1
        )  # pylint: disable=protected-access
        wait_for_eth_block(self.backend.eth_client, tx2_confirmation_block_number)
        for block_number in range(self.eth_fixture.eth2_tx_receipt.blockNumber + 1, tx2_confirmation_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
        with self.backend.sessionmaker() as session:
            account = session.query(Account).filter(Account.uuid == self.eth_account_uuid).one()
            self.assertEqual(account.available_amount, ETH1_AMOUNT + ETH2_AMOUNT)
            self.assertEqual(account.pending_amount, Decimal(0))
            self.assertEqual(
                session.query(Transaction)
                .filter(
                    Transaction.account_uuid == self.eth_account_uuid,
                    Transaction.status == TransactionStatus.COMPLETED,
                )
                .count(),
                2,
            )

    def test_get_available_and_pending_eth_balance(self) -> None:
        with self.backend.sessionmaker() as session:
            eth_account = session.query(Account).filter(Account.uuid == self.eth_account_uuid).one()
            amount = eth_account.pending_amount + eth_account.available_amount
            self.assertEqual(amount, ETH1_AMOUNT + ETH2_AMOUNT)

    def test_get_cumulative_deposits(self) -> None:
        self.assertEqual(
            self.backend.eth_client.get_cumulative_deposits(
                self.key_uuid,
                Currency.ETH,
                from_block_number=self.start_block + 1,
                to_block_number=self.eth_fixture.eth1_tx_receipt.blockNumber - 1,
            ),
            Decimal(0),
        )
        for block_number in range(
            self.eth_fixture.eth1_tx_receipt.blockNumber, self.eth_fixture.eth2_tx_receipt.blockNumber
        ):
            self.assertEqual(
                self.backend.eth_client.get_cumulative_deposits(
                    self.key_uuid, Currency.ETH, from_block_number=self.start_block + 1, to_block_number=block_number
                ),
                ETH1_AMOUNT,
            )

        self.assertEqual(
            self.backend.eth_client.get_cumulative_deposits(
                self.key_uuid,
                Currency.ETH,
                from_block_number=self.start_block + 1,
                to_block_number=self.eth_fixture.eth2_tx_receipt.blockNumber,
            ),
            ETH1_AMOUNT + ETH2_AMOUNT,
        )

    def test_key_approximate_bal(self) -> None:
        with self.backend.sessionmaker() as session:
            eth_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )

            expected_bal = ETH1_AMOUNT + ETH2_AMOUNT
            self.assertEqual(eth_key_currency.available_balance, expected_bal)

    def test_create_pending_transaction(self) -> None:
        amount = self.backend.eth_client.wei_to_eth(1)
        with self.backend.sessionmaker() as session:
            pending_tx_id, pending_tx_params_any_pb = self.backend.eth_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.ETH,
                destination_address=MAIN_ETH_ACCOUNT,
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
            pending_tx_pb = EthereumTxParams()
            self.assertTrue(pending_tx_params_any_pb.Unpack(pending_tx_pb))
            self.assertEqual(pending_tx.tx_params, pending_tx_params_any_pb)
            self.assertEqual(pending_tx.blockchain, Blockchain.ETH)
            estimated_tx_fee = self.backend.eth_client.wei_to_eth(pending_tx_pb.gas * pending_tx_pb.gasPrice)
            self.assertEqual(
                estimated_tx_fee,
                self.backend.eth_client.wei_to_eth(GAS_PRICE_WEI * 21_000),
            )
            self.assertIsNone(pending_tx.signed_tx)
            self.assertIsNone(pending_tx.txn_hash)
            self.assertIsNone(pending_tx.last_broadcast_at)
            self.assertIsNone(pending_tx.block_number)

            eth_key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(
                eth_key_currency_account.available_balance,
                ETH1_AMOUNT + ETH2_AMOUNT - amount - estimated_tx_fee,
            )

    def test_create_pending_transaction_admin(self) -> None:
        amount = self.backend.eth_client.wei_to_eth(1)
        admin_key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            admin_key = session.query(Key).filter(Key.key_uuid == admin_key_uuid).one()
            destination_address = admin_key.get_address(Blockchain.ETH)
            pending_tx_id, pending_tx_params_any_pb = self.backend.eth_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.ETH,
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
            pending_tx_pb = EthereumTxParams()
            self.assertTrue(pending_tx_params_any_pb.Unpack(pending_tx_pb))
            self.assertEqual(pending_tx.tx_params, pending_tx_params_any_pb)
            self.assertEqual(pending_tx.blockchain, Blockchain.ETH)
            estimated_tx_fee = self.backend.eth_client.wei_to_eth(pending_tx_pb.gas * pending_tx_pb.gasPrice)
            self.assertEqual(
                estimated_tx_fee,
                Decimal(GAS_PRICE_WEI * 21_000) / Decimal(10 ** 18),
            )
            self.assertIsNone(pending_tx.signed_tx)
            self.assertIsNone(pending_tx.txn_hash)
            self.assertIsNone(pending_tx.last_broadcast_at)
            self.assertIsNone(pending_tx.block_number)

            eth_key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(
                eth_key_currency_account.available_balance,
                ETH1_AMOUNT + ETH2_AMOUNT - amount - estimated_tx_fee,
            )

            dest_key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == admin_key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(dest_key_currency_account.pending_admin_deposits, 1)

    def test_create_pending_transaction_admin_fails(self) -> None:
        amount = self.backend.eth_client.wei_to_eth(1)
        new_key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            new_key = session.query(Key).filter(Key.key_uuid == new_key_uuid).one()
            destination_address = new_key.get_address(Blockchain.ETH)
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=new_key_uuid, account_uuid=self.eth_account_uuid
        )
        with self.assertRaises(RuntimeError):
            with self.backend.sessionmaker() as session:
                self.backend.eth_client.create_pending_transaction(
                    session,
                    amount=amount,
                    currency=Currency.ETH,
                    destination_address=destination_address,
                    key_type=KeyType.HOT,
                    should_dest_be_admin=True,
                )
                session.commit()

    def test_queue_hot_transactions(self) -> None:
        amount = self.backend.eth_client.wei_to_eth(1)
        with self.backend.sessionmaker() as session:
            pending_tx_id, ignored_pending_tx_any_pb = self.backend.eth_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.ETH,
                destination_address=MAIN_ETH_ACCOUNT,
                key_type=KeyType.HOT,
                should_dest_be_admin=False,
            )
            session.commit()
        with self.backend.sessionmaker() as session:
            self.backend.eth_client.queue_hot_transaction(session, pending_tx_id)
            session.commit()
        with self.backend.sessionmaker() as session:
            pending_eth_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            self.assertIsNotNone(pending_eth_tx.signed_tx)
            recovered_from_address = ETHAccount.recover_transaction(  # pylint: disable=no-value-for-parameter
                pending_eth_tx.signed_tx
            )
            self.assertEqual(recovered_from_address, self.eth_fixture.address)
        with self.assertRaises(NoResultFound):
            with self.backend.sessionmaker() as session:
                self.backend.eth_client.queue_hot_transaction(session, pending_tx_id)  # can't queue twice
                session.commit()

    def test_queue_cold_transaction(self) -> None:
        amount = self.backend.eth_client.wei_to_eth(1)
        with self.backend.sessionmaker() as session:
            pending_tx_id, pending_tx_any_pb = self.backend.eth_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.ETH,
                destination_address=MAIN_ETH_ACCOUNT,
                key_type=KeyType.HOT,
                should_dest_be_admin=False,
            )
            session.commit()
        tx_params_pb = EthereumTxParams()
        self.assertTrue(pending_tx_any_pb.Unpack(tx_params_pb))
        tx_params = self.backend.eth_client._deserialize_tx_params(tx_params_pb)  # pylint: disable=protected-access
        account = ETHAccount.from_key(self.eth_fixture.private_key)  # pylint: disable=no-value-for-parameter
        signed_tx = account.sign_transaction(tx_params)
        with self.backend.sessionmaker() as session:
            blockchain_transaction_identifier = self.backend.eth_client.queue_cold_transaction(
                session, pending_tx_id, signed_tx.rawTransaction
            )
            self.assertEqual(
                self.backend.eth_client._create_withdrawal_transaction_identifier(  # pylint: disable=protected-access
                    signed_tx.hash
                ),
                blockchain_transaction_identifier,
            )
            session.commit()
        with self.backend.sessionmaker() as session:
            pending_eth_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            self.assertIsNotNone(pending_eth_tx.signed_tx)
            recovered_from_address = ETHAccount.recover_transaction(  # pylint: disable=no-value-for-parameter
                pending_eth_tx.signed_tx
            )
            self.assertEqual(recovered_from_address, self.eth_fixture.address)
        with self.assertRaises(NoResultFound):
            with self.backend.sessionmaker() as session:
                self.backend.eth_client.queue_hot_transaction(session, pending_tx_id)  # can't queue twice
                session.commit()

    def test_broadcast_reconcile_prune(self) -> None:
        admin_key_uuid = self.backend.key_client.make_new_hot_key()
        with self.backend.sessionmaker() as session:
            admin_key = session.query(Key).filter(Key.key_uuid == admin_key_uuid).one()
            destination_address = admin_key.get_address(Blockchain.ETH)
            amount = self.backend.eth_client.wei_to_eth(1)
            pending_tx_id, ignored_pending_tx_any_pb = self.backend.eth_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.ETH,
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
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(admin_key_currency.pending_admin_deposits, 1)
        with self.backend.sessionmaker() as session:
            blockchain_transaction_identifier = self.backend.eth_client.queue_hot_transaction(session, pending_tx_id)
            session.commit()
        wait_for_eth_block(self.backend.eth_client, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        with self.backend.sessionmaker() as session:
            pending_eth_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            txn_hash = pending_eth_tx.txn_hash
            estimated_tx_fee = self.backend.eth_client.wei_to_eth(GAS_PRICE_WEI * 21_000)
            tx_params_any_pb = pending_eth_tx.tx_params
            tx_params = EthereumTxParams()
            self.assertTrue(tx_params_any_pb.Unpack(tx_params))
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

            eth_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )

            available_balance_with_estimated_fee = eth_key_currency.available_balance
            original_balance = available_balance_with_estimated_fee + estimated_tx_fee
            gas_price_wei = tx_params.gasPrice

            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == admin_key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(admin_key_currency.pending_admin_deposits, 1)

        # it SHOULD be included within the next block
        tx_receipt = cast(TxReceipt, self.w3.eth.waitForTransactionReceipt(txn_hash, timeout=20))
        self.assertEqual(
            self.backend.eth_client._create_withdrawal_transaction_identifier(  # pylint: disable=protected-access
                txn_hash
            ),
            blockchain_transaction_identifier,
        )
        reconcile_block_number = tx_receipt.blockNumber
        prune_block_number = reconcile_block_number + self.backend.eth_client.num_confirmations - 1
        gas_used = tx_receipt.gasUsed
        gas_used_wei = gas_used * gas_price_wei
        gas_used_eth = self.backend.eth_client.wei_to_eth(gas_used_wei)
        expected_new_balance = original_balance - gas_used_eth
        self.assertTrue(tx_receipt["status"])
        for block_number in range(self.eth_fixture.eth2_tx_receipt.blockNumber + 2, reconcile_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
        with self.backend.sessionmaker() as session:
            eth_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(eth_key_currency.available_balance, expected_new_balance)

            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == admin_key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(admin_key_currency.pending_admin_deposits, 1)

            pending_eth_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            self.assertEqual(pending_eth_tx.block_number, reconcile_block_number)
        wait_for_eth_block(self.backend.eth_client, prune_block_number)
        for block_number in range(reconcile_block_number + 1, prune_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
        with self.backend.sessionmaker() as session:
            admin_key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.currency == Currency.ETH,
                    KeyCurrencyAccount.key_uuid == key_uuid,
                )
                .one()
            )
            # the deposits are no longer pending
            self.assertEqual(admin_key_currency.pending_admin_deposits, 0)

            # no more pending transactions; they've been deleted
            self.assertEqual(
                session.query(BlockchainWithdrawal)
                .filter(BlockchainWithdrawal.pending_admin_deposits_reconciled.is_(False))
                .count(),
                0,
            )

    def test_void_transaction_and_broadcast(self) -> None:
        amount = self.backend.eth_client.wei_to_eth(3)
        with self.backend.sessionmaker() as session:
            pending_tx_id, ignored_pending_tx_any_pb = self.backend.eth_client.create_pending_transaction(
                session,
                amount=amount,
                currency=Currency.ETH,
                destination_address=MAIN_ETH_ACCOUNT,
                key_type=KeyType.HOT,
                should_dest_be_admin=False,
            )
            session.commit()
        wait_for_eth_block(self.backend.eth_client, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        estimated_tx_fee = self.backend.eth_client.wei_to_eth(GAS_PRICE_WEI * 21_000)
        with self.backend.sessionmaker() as session:
            pending_eth_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            # should be replaced with a transaction of 1
            tx_params_any_pb = pending_eth_tx.tx_params
            tx_params = EthereumTxParams()
            self.assertTrue(tx_params_any_pb.Unpack(tx_params))
            self.assertEqual(tx_params.gas, 21000)  # send gas is 21000
            # to address should be firm controlled
            key = (
                session.query(Key)
                .filter(
                    BlockchainAddressKey.blockchain == Blockchain.ETH,
                    BlockchainAddressKey.address == tx_params.toAddress,
                    BlockchainAddressKey.key_uuid == Key.key_uuid,
                )
                .one()
            )
            self.assertIn(key.key_type, (KeyType.COLD, KeyType.HOT))
            # assert that the account is not assigned and has a pending deposit
            key_currency = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == key.key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(key_currency.account_uuid, ADMIN_UUID)
            self.assertEqual(key_currency.pending_admin_deposits, 1)

            eth_key_currency_account = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.key_uuid == self.key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(
                eth_key_currency_account.available_balance,
                ETH1_AMOUNT + ETH2_AMOUNT - estimated_tx_fee - self.backend.eth_client.wei_to_eth(tx_params.value),
            )
        # process the next block so we will broadcast the transaction
        wait_for_eth_block(self.backend.eth_client, self.eth_fixture.eth2_tx_receipt.blockNumber + 2)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.eth_fixture.eth2_tx_receipt.blockNumber + 2)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.eth_fixture.eth2_tx_receipt.blockNumber + 2)
        with self.backend.sessionmaker() as session:
            pending_eth_tx = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid == pending_tx_id,
                )
                .one()
            )
            txn_hash = pending_eth_tx.txn_hash

        # it SHOULD be included within the next block
        tx_receipt = cast(TxReceipt, self.w3.eth.waitForTransactionReceipt(txn_hash, timeout=20))
        self.assertTrue(tx_receipt["status"])


class TestETHInitialBalance(BaseBackendTestCase):
    # Using a separate class since we don't want the same setUp method
    # specifically, we do NOT want to manually track the key, since thatis
    # what we are testing
    backend: Backend
    w3: web3.Web3
    channel: grpc.Channel
    start_block: int
    fixture_container: EthFixturesContainer

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.w3 = cls.backend.eth_client._w3  # pylint: disable=protected-access
        start_block = cls.backend.eth_client.start_block_number
        cls.start_block = start_block
        num_tests = len(list(filter(lambda x: x.startswith("test_"), dir(cls))))
        cls.fixture_container = EthFixturesContainer(cls.backend.eth_client, num_tests)

    def setUp(self) -> None:
        super().setUp()
        self.eth_fixture = self.fixture_container()
        for block_number in range(self.start_block, self.eth_fixture.eth2_tx_receipt.blockNumber + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
        with self.backend.sessionmaker() as session:
            # add an ethereum account
            eth_account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.ETH,
                account_type=AccountType.DEPOSIT_ACCOUNT,
            )
            session.add(eth_account)
            session.commit()
            self.eth_account_uuid = eth_account.uuid

    def test_late_import(self) -> None:
        private_key_bn = petlib.bn.Bn.from_binary(self.eth_fixture.private_key)
        key_uuid = self.backend.key_client.import_hot_key(private_key_bn)
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=key_uuid,
            account_uuid=self.eth_account_uuid,
        )
        wait_for_eth_block(self.backend.eth_client, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.eth_fixture.eth2_tx_receipt.blockNumber + 1)
        with self.backend.sessionmaker() as session:
            key_currency_block = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.key_uuid == key_uuid,
                    KeyCurrencyBlock.currency == Currency.ETH,
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
                    KeyAccountCommitment.account_uuid == self.eth_account_uuid,
                    KeyAccountCommitment.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(key_currency_block.block_number, key_currency_account.initial_balance_block_number)
            self.assertEqual(key_currency_block.block_number, key_account_commitment.block_number)
            self.assertEqual(key_currency_account.initial_balance, ETH1_AMOUNT + ETH2_AMOUNT)
            self.assertEqual(key_currency_account.available_balance, ETH1_AMOUNT + ETH2_AMOUNT)

    def test_late_import_with_withdrawal(self) -> None:
        withdrawn_amount_wei = 3

        tx_params = {
            "to": MAIN_ETH_ACCOUNT,
            "value": withdrawn_amount_wei,
            "gas": 21000,
            "gasPrice": 18,
            "nonce": 0,
            "chainId": self.backend.eth_client._chain_id,  # pylint: disable=protected-access
        }
        total_debit = self.backend.eth_client.wei_to_eth(withdrawn_amount_wei + 21000 * 18)
        account = ETHAccount.from_key(self.eth_fixture.private_key)  # pylint: disable=no-value-for-parameter
        signed_tx = account.sign_transaction(tx_params)
        txn_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx3receipt = cast(TxReceipt, self.w3.eth.waitForTransactionReceipt(txn_hash))
        tx3_block_number = tx3receipt.blockNumber

        for block_number in range(self.eth_fixture.eth2_tx_receipt.blockNumber + 1, tx3_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
        private_key_bn = petlib.bn.Bn.from_binary(self.eth_fixture.private_key)
        key_uuid = self.backend.key_client.import_hot_key(private_key_bn)
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=key_uuid,
            account_uuid=self.eth_account_uuid,
        )
        wait_for_eth_block(self.backend.eth_client, tx3_block_number + 1)
        self.backend.blockchain_client.process_block(Blockchain.ETH, tx3_block_number + 1)

        with self.backend.sessionmaker() as session:
            key_currency_block = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.key_uuid == key_uuid,
                    KeyCurrencyBlock.currency == Currency.ETH,
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
                    KeyAccountCommitment.account_uuid == self.eth_account_uuid,
                    KeyAccountCommitment.key_uuid == KeyCurrencyAccount.key_uuid,
                    KeyCurrencyAccount.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(key_currency_block.block_number, key_currency_account.initial_balance_block_number)
            self.assertEqual(key_currency_block.block_number, key_account_commitment.block_number)
            # we are simply sending bitcoin to ourselves and burning the rest
            self.assertEqual(key_currency_account.initial_balance, ETH1_AMOUNT + ETH2_AMOUNT - total_debit)
            self.assertEqual(key_currency_account.available_balance, ETH1_AMOUNT + ETH2_AMOUNT - total_debit)


if __name__ == "__main__":
    unittest.main()
