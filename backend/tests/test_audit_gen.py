import logging
import os
import shutil
import time
import unittest
import uuid
from datetime import datetime
from decimal import Decimal
from tempfile import TemporaryDirectory
from typing import Optional, cast
from unittest.mock import patch

import grpc
import web3
from bitcoin.core import COIN
from common.constants import CURRENCY_PRECISIONS, Blockchain, Currency
from common.utils.datetime import get_current_datetime
from common.utils.grpc_channel import make_grpc_channel
from common.utils.uuid import bytes_to_uuid
from google.protobuf.message import Message
from protobufs.audit_pb2 import Account as AccountPB2
from protobufs.audit_pb2 import AccountDeltaGroup as AccountDeltaGroupPB2
from protobufs.audit_pb2 import Audit as AuditPB2
from protobufs.audit_pb2 import Key as KeyPB2
from protobufs.audit_pb2 import (
    KeyAccount,
    KeyAccountLiability,
    KeyCurrencyAsset,
    SolvencyProof,
)
from protobufs.audit_pb2 import UserKey as UserKeyPB2
from protobufs.institution.account_pb2 import AccountResponse, ListAccountsRequest
from protobufs.institution.account_pb2_grpc import AccountStub
from protobufs.institution.auth_pb2 import (
    MakeRegistrationChallengeRequest,
    RegisterRequest,
)
from protobufs.institution.auth_pb2_grpc import AuthStub
from protobufs.institution.deposit_pb2 import MakeDepositKeyRequest
from protobufs.institution.deposit_pb2_grpc import DepositStub
from protobufs.institution.exchange_pb2 import (
    InitiateExchangeRequest,
    ProcessExchangeRequest,
)
from protobufs.institution.exchange_pb2_grpc import ExchangeStub
from protobufs.institution.marketdata_pb2 import GetMarketExchangeRateRequest
from protobufs.institution.marketdata_pb2_grpc import MarketdataStub
from protobufs.institution.withdrawal_pb2 import (
    InitiateWithdrawalRequest,
    ProcessWithdrawalRequest,
)
from protobufs.institution.withdrawal_pb2_grpc import WithdrawalStub

from auditgen.generate_audit import AuditGen
from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.account_delta_group import AccountDeltaGroup
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.sql.user_key import UserKey
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.list_rpc import list_rpc_yield
from tests.base import BaseBackendTestCase
from tests.fixtures import (
    MAIN_ETH_ACCOUNT,
    TxInfo,
    generate_mock_auditgen_config,
    wait_for_bitcoin_tx,
    wait_for_eth_block,
)

LOGGER = logging.getLogger(__name__)


def mock_get_block_number_at_or_after_timestamp(
    self: BlockchainClient,
    blockchain: Blockchain,
    timestamp: datetime,  # pylint: disable=unused-argument
) -> int:
    latest_processed_block_number = self.get_latest_processed_block_number(blockchain)
    assert latest_processed_block_number is not None
    return latest_processed_block_number


def mock_get_latest_processed_block_timestamp_across_all_blockchains(
    self: BlockchainClient,  # pylint: disable=unused-argument
) -> datetime:
    return get_current_datetime()


class TestAuditGen(BaseBackendTestCase):
    tempdir: "TemporaryDirectory[str]"
    channel: grpc.Channel
    backend: Backend
    audit_gen: AuditGen
    auth_stub: AuthStub

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.audit_gen = AuditGen(
            generate_mock_auditgen_config(
                cls.tempdir.name, eth_start_block_number=cls.backend.config.eth_config.w3_config.start_block_number
            )
        )
        cls.auth_stub = AuthStub(cls.channel)

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.audit_gen.close()

    def _process_next_blocks(self) -> None:
        bitcoin_block = self.backend.blockchain_client.get_latest_processed_block_number(Blockchain.BTC)
        if bitcoin_block is None:
            bitcoin_block = self.backend.blockchain_client.get_start_block_number(Blockchain.BTC)
        else:
            bitcoin_block += 1

        eth_block = self.backend.blockchain_client.get_latest_processed_block_number(Blockchain.ETH)
        if eth_block is None:
            eth_block = self.backend.blockchain_client.get_start_block_number(Blockchain.ETH)
        else:
            eth_block += 1
        assert bitcoin_block is not None

        self._process_blocks(bitcoin_block=bitcoin_block, ethereum_block=eth_block)

    def _process_blocks(self, *, bitcoin_block: int, ethereum_block: int) -> None:
        # process blocks up to and include the `bitcoin_block` and `ethereum_block` params
        # do not process anything more than that
        LOGGER.info("processing till eth block %d; btc block %d", ethereum_block, bitcoin_block)

        def process_blockchain(blockchain: Blockchain, max_block: int) -> bool:
            latest_processed_block_number = self.backend.blockchain_client.get_latest_processed_block_number(blockchain)
            if latest_processed_block_number is None:
                block_to_process = self.backend.blockchain_client.get_start_block_number(blockchain)
            else:
                block_to_process = latest_processed_block_number + 1
            if block_to_process > max_block:
                return True
            latest_blockchain_block_number = self.backend.blockchain_client.get_latest_block_number_from_chain(
                blockchain
            )
            while block_to_process <= min(max_block, latest_blockchain_block_number):
                LOGGER.info("PROCESSING BLOCK %d on %s", block_to_process, latest_blockchain_block_number)
                self.backend.blockchain_client.process_block(blockchain, block_to_process)
                block_to_process += 1
            return False

        btc_finished = False
        eth_finished = False
        for _ in range(20):
            if not btc_finished:
                btc_finished = process_blockchain(Blockchain.BTC, bitcoin_block)
            if not eth_finished:
                eth_finished = process_blockchain(Blockchain.ETH, ethereum_block)
            if btc_finished and eth_finished:
                self.assertEqual(
                    self.backend.blockchain_client.get_latest_processed_block_number(Blockchain.BTC), bitcoin_block
                )
                self.assertEqual(
                    self.backend.blockchain_client.get_latest_processed_block_number(Blockchain.ETH), ethereum_block
                )
                return
            time.sleep(1)
        self.fail("Did not process blocks in 20 second timeout")

    def load_protobuf_from_file(self, base_directory: str, filepath: str) -> Message:
        complete_filepath = os.path.join(base_directory, "audit", filepath)
        with open(complete_filepath, "rb") as f:
            protobuf_bytes = f.read()
        message: Optional[Message] = None
        if filepath == "audit.bin":
            message = AuditPB2()
        if filepath == "solvency_proof.bin":
            message = SolvencyProof()
        if filepath.startswith("user_keys"):
            message = UserKeyPB2()
        if filepath.startswith("keys"):
            message = KeyPB2()
        if filepath.startswith("accounts"):
            message = AccountPB2()
        if filepath.startswith("key_accounts"):
            message = KeyAccount()
        if filepath.startswith("account_delta_groups"):
            message = AccountDeltaGroupPB2()
        if filepath.startswith("key_account_liabilities"):
            message = KeyAccountLiability()
        if filepath.startswith("key_currency_assets"):
            message = KeyCurrencyAsset()
        self.assertIsNotNone(message, "invalid filepath")
        assert message is not None
        self.assertTrue(message.ParseFromString(protobuf_bytes))
        return message

    @patch.object(
        BlockchainClient, "get_block_number_at_or_after_timestamp", mock_get_block_number_at_or_after_timestamp
    )
    @patch.object(
        BlockchainClient,
        "get_latest_processed_block_timestamp_across_all_blockchains",
        mock_get_latest_processed_block_timestamp_across_all_blockchains,
    )
    def test_audit_gen_user_key(self) -> None:  # type: ignore[misc]
        self._process_next_blocks()

        with TemporaryDirectory() as tempdir:
            self.audit_gen.generate_audit(tempdir)
            self.load_protobuf_from_file(tempdir, "audit.bin")
            self.load_protobuf_from_file(tempdir, "solvency_proof.bin")

            with self.backend.sessionmaker() as session:
                user_key = session.query(UserKey).one()

                self.load_protobuf_from_file(tempdir, f"user_keys/{user_key.user_key_uuid.hex}.bin")
            self.audit_gen.publish_audit(tempdir)

    @patch.object(
        BlockchainClient, "get_block_number_at_or_after_timestamp", mock_get_block_number_at_or_after_timestamp
    )
    @patch.object(
        BlockchainClient,
        "get_latest_processed_block_timestamp_across_all_blockchains",
        mock_get_latest_processed_block_timestamp_across_all_blockchains,
    )
    def test_audit_gen_account(self) -> None:  # type: ignore[misc]
        # create a new user. this will implicitley create deposit accounts -- once for each currency
        request = MakeRegistrationChallengeRequest(username="register_username")
        response = self.auth_stub.MakeRegistrationChallenge(request)
        attestation = self.soft_webauthn.create_credential(response.credentialRequest)
        register_request = RegisterRequest(challengeNonce=response.challengeRequest.nonce, attestation=attestation)
        register_response = self.auth_stub.Register(register_request)
        jwt = register_response.jwt

        channel = make_grpc_channel(
            self.config.grpc_server_config.grpc_config,
            jwt,
        )
        account_stub = AccountStub(channel)
        deposit_stub = DepositStub(channel)
        marketdata_stub = MarketdataStub(channel)
        exchange_stub = ExchangeStub(channel)
        withdrawal_stub = WithdrawalStub(channel)

        eth_deposit_address: Optional[str] = None
        gusd_deposit_address: Optional[str] = None
        btc_deposit_address: Optional[str] = None
        eth_account_uuid: Optional[uuid.UUID] = None
        gusd_account_uuid: Optional[uuid.UUID] = None

        for account_response in list_rpc_yield(ListAccountsRequest(), account_stub.ListAccounts):
            # create a deposit key
            assert isinstance(account_response, AccountResponse)
            deposit_key_request = MakeDepositKeyRequest(accountId=account_response.id)
            deposit_key_response = deposit_stub.MakeDepositKey(deposit_key_request)
            if account_response.currency == "ETH":
                eth_deposit_address = deposit_key_response.depositKey.address
                eth_account_uuid = bytes_to_uuid(account_response.id)
            if account_response.currency == "GUSD":
                gusd_account_uuid = bytes_to_uuid(account_response.id)
                gusd_deposit_address = deposit_key_response.depositKey.address
            if account_response.currency == "BTC":
                btc_deposit_address = deposit_key_response.depositKey.address

        assert eth_deposit_address is not None
        assert gusd_deposit_address is not None
        assert eth_account_uuid is not None
        assert gusd_account_uuid is not None
        assert btc_deposit_address is not None

        self._process_next_blocks()

        with TemporaryDirectory() as tempdir:
            self.audit_gen.generate_audit(tempdir)
            self.load_protobuf_from_file(tempdir, "audit.bin")
            self.load_protobuf_from_file(tempdir, "solvency_proof.bin")
            with self.backend.sessionmaker() as session:
                user_keys = session.query(UserKey).all()
                accounts = session.query(Account).all()
                key_account_commitments = session.query(KeyAccountCommitment).all()
                key = session.query(Key).one()  # should only be one used accross all accounts
                # no account delta groups
                # no key_account_liability
                # no key_currency_asset
                self.assertEqual(len(user_keys), 2)
                self.assertEqual(len(accounts), 3)
                for user_key in user_keys:
                    self.load_protobuf_from_file(tempdir, f"user_keys/{user_key.user_key_uuid.hex}.bin")
                for account in accounts:
                    self.load_protobuf_from_file(tempdir, f"accounts/{account.uuid.hex}.bin")
                self.load_protobuf_from_file(tempdir, f"keys/{key.key_uuid.hex}.bin")
                self.assertEqual(len(key_account_commitments), 3)
                for key_account_commitment in key_account_commitments:
                    self.load_protobuf_from_file(
                        tempdir,
                        f"key_accounts/{key_account_commitment.key_uuid.hex}-"
                        f"{key_account_commitment.account_uuid.hex}.bin",
                    )
            ignored_audit_publish_receipt = self.audit_gen.publish_audit(tempdir)
            shutil.move(
                tempdir + "/audit.tgz",
                os.path.join(os.path.dirname(__file__), "..", "..", "auditor", "tests", "audit_1.tgz"),
            )

        # deposit a drop of eth, gusd, and btc
        w3 = self.backend.eth_client._w3  # pylint: disable=protected-access
        eth_deposit_amount = Decimal("0.1")
        btc_deposit_amount = Decimal("1.0")
        gusd_deposit_amount = Decimal("10000")

        # eth deposit
        eth1_hash = w3.eth.send_transaction(
            {
                "from": MAIN_ETH_ACCOUNT,
                "to": eth_deposit_address,
                "value": self.backend.eth_client.eth_to_wei(eth_deposit_amount),
            }
        )

        admin_key_uuid = self.backend.key_client.make_new_hot_key()

        with self.backend.sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == admin_key_uuid).one()
            admin_eth_address = key.get_address(Blockchain.ETH)

        eth2_hash = w3.eth.send_transaction(
            {
                "from": MAIN_ETH_ACCOUNT,
                "to": admin_eth_address,
                "value": self.backend.eth_client.eth_to_wei(eth_deposit_amount),
            }
        )

        # gusd deposit
        gusd1_hash = (
            self.backend.eth_client._stablecoin_to_contract[Currency.GUSD]  # pylint: disable=protected-access
            .functions.transfer(
                gusd_deposit_address,
                int(gusd_deposit_amount * CURRENCY_PRECISIONS[Currency.GUSD]),
            )
            .transact({"from": MAIN_ETH_ACCOUNT})
        )

        # btc deposit
        with self.backend.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            txid1 = proxy.sendtoaddress(btc_deposit_address, int(btc_deposit_amount * COIN))
        tx1: Optional[TxInfo] = None

        eth1_tx_receipt = cast(web3.types.TxReceipt, w3.eth.waitForTransactionReceipt(eth1_hash, timeout=20))
        eth2_tx_receipt = cast(web3.types.TxReceipt, w3.eth.waitForTransactionReceipt(eth2_hash, timeout=20))
        gusd1_tx_receipt = cast(web3.types.TxReceipt, w3.eth.waitForTransactionReceipt(gusd1_hash, timeout=20))

        wait_for_eth_block(self.backend.eth_client, eth1_tx_receipt.blockNumber + 1)  # block at which it's confirmed
        wait_for_eth_block(self.backend.eth_client, eth2_tx_receipt.blockNumber + 1)  # block at which it's confirmed
        wait_for_eth_block(self.backend.eth_client, gusd1_tx_receipt.blockNumber + 1)  # block at which it's confirmed
        with self.backend.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            tx1 = wait_for_bitcoin_tx(proxy, txid1)
        self._process_blocks(  # pylint: disable=protected-access
            bitcoin_block=tx1.blockheight + 1,
            ethereum_block=max(eth1_tx_receipt.blockNumber, gusd1_tx_receipt.blockNumber, eth2_tx_receipt.blockNumber)
            + 1,
        )  # confirm deposit

        exchange_rate_request = GetMarketExchangeRateRequest(
            fromCurrency=Currency.ETH.name, toCurrency=Currency.GUSD.name
        )
        exchange_rate_response = marketdata_stub.GetMarketExchangeRate(exchange_rate_request)

        initiate_exchange_request = InitiateExchangeRequest(
            exchangeRateJWT=exchange_rate_response.exchangeRateJWT,
            amount="0.01",
            fromAccountId=eth_account_uuid.bytes,
            toAccountId=gusd_account_uuid.bytes,
        )
        initiate_exchange_response = exchange_stub.InitiateExchange(initiate_exchange_request)
        exchange_assertion = self.soft_webauthn.request_assertion(
            initiate_exchange_response.challengeRequest, initiate_exchange_response.credentialRequest
        )
        process_exchange_request = ProcessExchangeRequest(
            id=initiate_exchange_response.id, assertion=exchange_assertion
        )
        exchange_stub.ProcessExchange(process_exchange_request)

        initiate_request = InitiateWithdrawalRequest(
            amount=str("0.05"),
            fromAccountId=eth_account_uuid.bytes,
            destinationAddress=MAIN_ETH_ACCOUNT,
        )
        initiate_withdrawal_response = withdrawal_stub.InitiateWithdrawal(initiate_request)
        withdrawal_assertion = self.soft_webauthn.request_assertion(
            initiate_withdrawal_response.challengeRequest, initiate_withdrawal_response.credentialRequest
        )
        process_withdrawal_request = ProcessWithdrawalRequest(
            id=initiate_withdrawal_response.id, assertion=withdrawal_assertion
        )
        withdrawal_stub.ProcessWithdrawal(process_withdrawal_request)

        confirmed = False
        for _ in range(20):
            btc_block = self.backend.blockchain_client.get_latest_block_number_from_chain(Blockchain.BTC)
            eth_block = self.backend.blockchain_client.get_latest_block_number_from_chain(Blockchain.ETH)
            self._process_blocks(bitcoin_block=btc_block, ethereum_block=eth_block)
            with self.backend.sessionmaker() as session:
                unconfirmed_txn_count = (
                    session.query(BlockchainWithdrawal).filter(BlockchainWithdrawal.block_number.is_(None)).count()
                )
                if unconfirmed_txn_count > 0:
                    time.sleep(1)
                    continue
                confirmed = True
                break
        self.assertTrue(confirmed, "failed to confirm transactions")
        # process one more set of blocks to ensure that the confirmed block is reflected in the database
        self._process_next_blocks()

        # TODO generate and validate the audit
        with TemporaryDirectory() as tempdir:
            self.audit_gen.generate_audit(tempdir)
            self.load_protobuf_from_file(tempdir, "audit.bin")
            self.load_protobuf_from_file(tempdir, "solvency_proof.bin")
            with self.backend.sessionmaker() as session:
                account_delta_groups = session.query(AccountDeltaGroup).all()
                keys = session.query(Key).all()
                self.assertEqual(len(keys), 4)
                key_account_commitments = session.query(KeyAccountCommitment).all()
                self.assertEqual(len(account_delta_groups), 2)  # the exchange and the withdrawal
                self.assertEqual(len(key_account_commitments), 3)
                for key_account_commitment in key_account_commitments:
                    self.load_protobuf_from_file(
                        tempdir,
                        f"key_account_liabilities/{key_account_commitment.key_uuid.hex}-"
                        f"{key_account_commitment.account_uuid.hex}.bin",
                    )
                for account_delta_group in account_delta_groups:
                    self.load_protobuf_from_file(tempdir, f"account_delta_groups/{account_delta_group.uuid.hex}.bin")
                for currency in Currency:
                    for key in keys:
                        self.load_protobuf_from_file(
                            tempdir, f"key_currency_assets/{key.key_uuid.hex}-{currency.name}.bin"
                        )
                ignored_audit_publish_receipt = self.audit_gen.publish_audit(tempdir)
                shutil.move(
                    tempdir + "/audit.tgz",
                    os.path.join(os.path.dirname(__file__), "..", "..", "auditor", "tests", "audit_2.tgz"),
                )


if __name__ == "__main__":
    unittest.main()
