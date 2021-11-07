import time
import unittest
import uuid
from decimal import Decimal
from typing import List, cast

import grpc
import petlib.bn
import petlib.ec
from common.constants import (
    CURRENCY_PRECISIONS,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_GROUP,
    Blockchain,
    Currency,
)
from common.utils.uuid import bytes_to_uuid
from protobufs.account_pb2 import AccountDeltaGroupChallengeRequest, AccountType
from protobufs.eth_pb2 import EthereumTxParams
from protobufs.institution.account_pb2 import TransactionStatus, TransactionType
from protobufs.institution.withdrawal_pb2 import (
    InitiateWithdrawalRequest,
    ProcessWithdrawalRequest,
)
from protobufs.institution.withdrawal_pb2_grpc import WithdrawalStub
from web3.types import TxReceipt

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.account_delta_group import AccountDeltaGroup
from backend.sql.account_delta_group_blockchain_transaction import (
    AccountDeltaGroupBlockchainTransaction,
)
from backend.sql.blockchain_transaction import BlockchainTransaction
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.key import Key
from backend.sql.transaction import Transaction
from backend.utils.jwt_client import JWTClient
from tests.base import BaseBackendTestCase
from tests.fixtures import MAIN_ETH_ACCOUNT, MOCK_JWT_CONFIG, MOCK_USER_UUID

WITHDRAWAL_AMOUNT = Decimal("0.0001")
DEPOSIT_AMOUNT = Decimal("0.1")


class TestWithdrawal(BaseBackendTestCase):
    withdrawal_stub: WithdrawalStub
    jwt_client: JWTClient
    channel: grpc.Channel
    backend: Backend

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.withdrawal_stub = WithdrawalStub(cls.channel)
        cls.jwt_client = JWTClient(MOCK_JWT_CONFIG)

    def _wait_for_block(self, block_number: int, timeout_seconds: int = 20) -> None:
        for i in range(timeout_seconds):
            if self.backend.eth_client.get_latest_block_number_from_chain() >= block_number:
                break
            if i < timeout_seconds - 1:
                time.sleep(1)
                continue
            raise RuntimeError("Timeout")

    def setUp(self) -> None:
        super().setUp()
        with self.backend.sessionmaker() as session:
            eth_account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.ETH,
                account_type=AccountType.DEPOSIT_ACCOUNT,
            )
            session.add(eth_account)
            gusd_account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.GUSD,
                account_type=AccountType.DEPOSIT_ACCOUNT,
            )
            session.add(gusd_account)
            session.commit()
            self.eth_account_uuid = eth_account.uuid
            self.gusd_account_uuid = gusd_account.uuid
        eth_client = self.backend.eth_client

        self.key_uuid = self.backend.key_client.make_new_hot_key()
        self.backend.key_client.assign_key_for_deposits_to_account(
            key_uuid=self.key_uuid, account_uuid=self.eth_account_uuid
        )
        start_block = eth_client.start_block_number
        # process a block so the keys are tracked
        self._wait_for_block(start_block)
        self.backend.blockchain_client.process_block(Blockchain.ETH, start_block)
        with self.backend.sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == self.key_uuid).one()
            self.deposit_address = key.get_address(Blockchain.ETH)

            w3 = eth_client._w3  # pylint: disable=protected-access

            gusd_contract = eth_client._stablecoin_to_contract[Currency.GUSD]  # pylint: disable=protected-access

            # Make a tracked deposit for both eth and gusd
            eth_tx1_hash = w3.eth.send_transaction(
                {
                    "from": MAIN_ETH_ACCOUNT,
                    "to": self.deposit_address,
                    "value": self.backend.eth_client.eth_to_wei(DEPOSIT_AMOUNT),
                }
            )
            gusd_tx1_hash = gusd_contract.functions.transfer(
                self.deposit_address,
                10000,
            ).transact({"from": MAIN_ETH_ACCOUNT})
            self.eth_tx1 = cast(TxReceipt, w3.eth.waitForTransactionReceipt(eth_tx1_hash, timeout=20))
            self.gusd_tx1 = cast(TxReceipt, w3.eth.waitForTransactionReceipt(gusd_tx1_hash, timeout=20))

        # process the blocks until both are confirmed
        # subtracting 1 since the block at which it hits the blockchain is considered 1 confirmation
        self.end_block = (
            max(self.eth_tx1.blockNumber, self.gusd_tx1.blockNumber)
            + eth_client._num_confirmations  # pylint: disable=protected-access
            - 1
        )
        self._wait_for_block(self.end_block)
        for block_number in range(start_block + 1, self.end_block + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)

        # assert that we have the $$
        with self.backend.sessionmaker() as session:
            account = session.query(Account).filter(Account.uuid == self.eth_account_uuid).one()
            self.assertEqual(account.available_amount, DEPOSIT_AMOUNT)

    def test_initiate_withdrawal(self) -> None:
        request = InitiateWithdrawalRequest(
            amount=str(WITHDRAWAL_AMOUNT.normalize()),
            fromAccountId=self.eth_account_uuid.bytes,
            destinationAddress=MAIN_ETH_ACCOUNT,
        )
        response = self.withdrawal_stub.InitiateWithdrawal(request)

        challenge_request = response.challengeRequest
        request_any_pb = challenge_request.request
        withdrawal_challenge_request = AccountDeltaGroupChallengeRequest()
        self.assertTrue(request_any_pb.Unpack(withdrawal_challenge_request))
        transactions = withdrawal_challenge_request.transactions
        # there should be an ETH transaction for the amount we're requesting
        # and a gusd transaction for a dummy amount
        # it's hard to verify the gusd one (would need to decode the input)
        # but let's verify the contract address anyways

        # TODO validate the account delta and the account delta group
        found_real = False

        for transaction in transactions:
            self.assertEqual(transaction.blockchain, Blockchain.ETH.name)
            tx_params_any_pb = transaction.txParams
            eth_tx_params = EthereumTxParams()
            self.assertTrue(tx_params_any_pb.Unpack(eth_tx_params))
            if eth_tx_params.value == 0:
                # it's the gusd (decoy) one
                self.assertEqual(
                    eth_tx_params.toAddress,
                    self.backend.eth_client._stablecoin_to_contract[  # pylint: disable=protected-access
                        Currency.GUSD
                    ].address,
                )
            else:
                # it's eth. could be decoy eth (real) one
                if (
                    eth_tx_params.toAddress == MAIN_ETH_ACCOUNT
                    and eth_tx_params.value == self.backend.eth_client.eth_to_wei(WITHDRAWAL_AMOUNT)
                ):
                    found_real = True
        self.assertTrue(found_real)

        public_commitments = withdrawal_challenge_request.commitments
        for revealed_commitment, public_commitment in zip(response.revealedCommitments, public_commitments):
            self.assertEqual(public_commitment.accountId, revealed_commitment.accountId)
            account_id = bytes_to_uuid(public_commitment.accountId)
            amount_bn = petlib.bn.Bn.from_decimal(revealed_commitment.commitment.x)
            self.assertEqual(
                petlib.ec.EcPt.from_binary(public_commitment.commitment, SECP256K1_GROUP),
                petlib.bn.Bn.from_decimal(revealed_commitment.commitment.x) * SECP256K1_GENERATOR
                + petlib.bn.Bn.from_decimal(revealed_commitment.commitment.r) * SECP256K1_ALTERNATIVE_GENERATOR,
            )
            expected_amount = Decimal(0)
            if account_id == self.eth_account_uuid:
                expected_amount = -WITHDRAWAL_AMOUNT
                expected_amount *= Decimal(CURRENCY_PRECISIONS[Currency.ETH])
            expected_amount_int = int(expected_amount)
            expected_amount_bn = (
                petlib.bn.Bn(expected_amount_int)
                if expected_amount_int >= 0
                else -petlib.bn.Bn.from_decimal(str(-expected_amount_int))
            )
            self.assertEqual(amount_bn, expected_amount_bn)

    def test_process_withdrawal(self) -> None:
        initiate_request = InitiateWithdrawalRequest(
            amount=str(WITHDRAWAL_AMOUNT.normalize()),
            fromAccountId=self.eth_account_uuid.bytes,
            destinationAddress=MAIN_ETH_ACCOUNT,
        )
        initiate_response = self.withdrawal_stub.InitiateWithdrawal(initiate_request)
        assertion = self.soft_webauthn.request_assertion(
            initiate_response.challengeRequest, initiate_response.credentialRequest
        )
        process_request = ProcessWithdrawalRequest(id=initiate_response.id, assertion=assertion)
        self.withdrawal_stub.ProcessWithdrawal(process_request)

        with self.backend.sessionmaker() as session:
            eth_account = session.query(Account).filter(Account.uuid == self.eth_account_uuid).one()
            self.assertEqual(eth_account.available_amount, DEPOSIT_AMOUNT - WITHDRAWAL_AMOUNT)
            self.assertEqual(eth_account.pending_amount, -WITHDRAWAL_AMOUNT)

            eth_transaction = (
                session.query(Transaction)
                .filter(
                    Transaction.account_uuid == self.eth_account_uuid,
                    Transaction.transaction_type == TransactionType.WITHDRAWAL,
                    Transaction.status == TransactionStatus.COMPLETED,
                )
                .one()
            )
            self.assertEqual(eth_transaction.amount, -WITHDRAWAL_AMOUNT)

            account_delta_group_uuid = bytes_to_uuid(initiate_response.id)

            adg = session.query(AccountDeltaGroup).filter(AccountDeltaGroup.uuid == account_delta_group_uuid).one()
            self.assertEqual(adg.status, TransactionStatus.COMPLETED)

            # Validate that the account delta group blockchain identifiers are set
            blockchain_transactions_and_adgbts = (
                session.query(BlockchainTransaction, AccountDeltaGroupBlockchainTransaction)
                .filter(
                    BlockchainTransaction.blockchain_transaction_identifier
                    == AccountDeltaGroupBlockchainTransaction.blockchain_transaction_identifier,
                    AccountDeltaGroupBlockchainTransaction.account_delta_group_uuid == adg.uuid,
                )
                .all()
            )
            self.assertEqual(len(blockchain_transactions_and_adgbts), 3)
            blockchain_client_transaction_uuids: List[uuid.UUID] = []
            blockchain_transaction_identifiers: List[str] = []
            for blockchain_transaction, adgbt in blockchain_transactions_and_adgbts:
                self.assertEqual(blockchain_transaction.blockchain, Blockchain.ETH)
                self.assertEqual(blockchain_transaction.transaction_uuid, eth_transaction.uuid)
                self.assertIsNotNone(adgbt.blockchain_transaction_identifier)
                self.assertIsNotNone(adgbt.blockchain, Blockchain.ETH)
                blockchain_client_transaction_uuids.append(adgbt.blockchain_withdrawal_uuid)
                blockchain_transaction_identifiers.append(adgbt.blockchain_transaction_identifier)
        # send it onto the chain
        self._wait_for_block(self.end_block + 1)
        self.backend.blockchain_client.process_block(Blockchain.ETH, self.end_block + 1)
        with self.backend.sessionmaker() as session:
            # get the pending eth transactions from the chain
            pending_eth_transactions = (
                session.query(BlockchainWithdrawal)
                .filter(
                    BlockchainWithdrawal.uuid.in_(blockchain_client_transaction_uuids),
                )
                .all()
            )
            txn_hashes = [pending_eth_transaction.txn_hash for pending_eth_transaction in pending_eth_transactions]
            last_block_number = 0
            for txn_hash in txn_hashes:
                self.assertIsNotNone(txn_hash)
                tx_receipt = cast(
                    TxReceipt,
                    self.backend.eth_client._w3.eth.waitForTransactionReceipt(  # pylint: disable=protected-access
                        txn_hash
                    ),
                )
                last_block_number = max(last_block_number, tx_receipt.blockNumber)
        for block_number in range(self.end_block + 2, last_block_number + 1):
            self.backend.blockchain_client.process_block(Blockchain.ETH, block_number)
        with self.backend.sessionmaker() as session:
            # assert that we put the block number in the blockchain transaction table
            blockchain_transactions = (
                session.query(BlockchainTransaction)
                .filter(
                    BlockchainTransaction.blockchain == Blockchain.ETH,
                    BlockchainTransaction.blockchain_transaction_identifier.in_(blockchain_transaction_identifiers),
                )
                .all()
            )
            for blockchain_transaction in blockchain_transactions:
                self.assertGreater(blockchain_transaction.block_number, self.end_block + 1)
                self.assertLessEqual(blockchain_transaction.block_number, last_block_number)


if __name__ == "__main__":
    unittest.main()
