import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import grpc
import sqlalchemy
from common.constants import Blockchain, Currency
from common.utils.uuid import generate_uuid4
from google.protobuf.any_pb2 import Any
from google.protobuf.message import Message
from protobufs.account_pb2 import UnsignedBlockchainTransacton
from protobufs.bitcoin_pb2 import BitcoinTransactionSource, BitcoinTxParams
from protobufs.eth_pb2 import EthereumTxParams
from protobufs.validator.auditor_pb2 import (
    GetAuditRequest,
    GetLatestAuditVersionRequest,
    ListKeyAccountsRequest,
    ValidateUnsignedBlockchainTransactionRequest,
)
from protobufs.validator.auditor_pb2_grpc import AuditorStub

from auditor.audit_processor import AuditProcessor
from auditor.auditor import Auditor
from auditor.config import AuditorConfig
from auditor.sql.account import Account
from auditor.utils.blockchain_client.client import BlockchainClient
from auditor.utils.key_client import KeyClient
from auditor.utils.marketdata_client import MarketdataClient
from auditor.utils.webauthn_client import WebauthnClient
from tests.base import BaseAuditorTestCase
from tests.fixtures import (
    mock_process_new_block,
    mock_return_none,
    mock_return_true,
    mock_return_zero,
)


@patch.object(AuditProcessor, "process_new_blocks", mock_process_new_block)
@patch.object(AuditProcessor, "validate_block_timestamps", mock_return_none)
@patch.object(BlockchainClient, "get_latest_block_number_from_chain", lambda _, __: 1_000_000)
@patch.object(BlockchainClient, "validate_tx_in_chain", mock_return_true)
@patch.object(BlockchainClient, "get_balance_from_chain", mock_return_zero)
@patch.object(AuditProcessor, "validate_exchange_rates", mock_return_none)
@patch.object(BlockchainClient, "get_block_metadata_from_chain", mock_return_none)
class TestServicerAudit(BaseAuditorTestCase):
    auditor: Auditor
    sessionmaker: sqlalchemy.orm.sessionmaker
    key_client: KeyClient
    webauthn_client: WebauthnClient
    blockchain_client: BlockchainClient
    marketdata_client: MarketdataClient
    config: AuditorConfig
    audit_stub: AuditorStub
    channel: grpc.Channel

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.key_client = cls.auditor.key_client
        cls.webauthn_client = cls.auditor.webauthn_client
        cls.blockchain_client = cls.auditor.blockchain_client
        cls.marketdata_client = cls.auditor.marketdata_client
        cls.config = cls.config
        cls.sessionmaker = cls.auditor.sessionmaker
        cls.audit_stub = AuditorStub(cls.channel)

    def _load_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            audit_tarball = os.path.join(tempdir, str(generate_uuid4()) + ".tgz")
            shutil.copy(os.path.join(os.path.dirname(__file__), "audit_3.tgz"), audit_tarball)
            self.auditor.audit_processor.process_audit(audit_tarball)

    def test_get_latest_audit_version(self) -> None:
        self._load_audit()
        resp = self.audit_stub.GetLatestAuditVersion(GetLatestAuditVersionRequest())
        self.assertEqual(resp.version, 1)

    def test_get_audit(self) -> None:
        self._load_audit()
        resp = self.audit_stub.GetAudit(GetAuditRequest(version=1))
        self.assertEqual(resp.audit.auditVersion, 1)

    def test_list_key_accounts(self) -> None:
        self._load_audit()
        with self.sessionmaker() as session:
            account = session.query(Account).filter(Account.currency == Currency.ETH).one()
            account_uuid = account.uuid
        resp = self.audit_stub.ListKeyAccounts(
            ListKeyAccountsRequest(request=ListKeyAccountsRequest.Request(accountId=account_uuid.bytes))
        )
        self.assertEqual(len(resp.response), 1)


class TestServicerChain(BaseAuditorTestCase):
    auditor: Auditor
    sessionmaker: sqlalchemy.orm.sessionmaker
    config: AuditorConfig
    audit_stub: AuditorStub
    channel: grpc.Channel

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.config = cls.config
        cls.sessionmaker = cls.auditor.sessionmaker
        cls.audit_stub = AuditorStub(cls.channel)

    def _test_validate_helper(self, blockchain: Blockchain, tx_params: Message) -> bool:
        tx_params_any = Any()
        tx_params_any.Pack(tx_params)
        resp = self.audit_stub.ValidateUnsignedBlockchainTransaction(
            ValidateUnsignedBlockchainTransactionRequest(
                transaction=UnsignedBlockchainTransacton(
                    blockchain=blockchain.name,
                    txParams=tx_params_any,
                ),
            )
        )
        return resp.wouldBeNew

    def test_validate_unsigned_blockchain_transaction_eth(self) -> None:
        self.auditor.blockchain_client.process_block(
            Blockchain.ETH, self.auditor.blockchain_client.get_start_block_number(Blockchain.ETH)
        )
        eth_tx_params = EthereumTxParams(
            fromAddress="0xD0Ecf1c8079Bd1D933a9Bc25cC9e2451db863Ca3",
            nonce=1,
        )
        self.assertTrue(self._test_validate_helper(Blockchain.ETH, eth_tx_params))

    def test_validate_unsigned_blockchain_transaction_btc(self) -> None:
        self.auditor.blockchain_client.process_block(
            Blockchain.BTC, self.auditor.blockchain_client.get_start_block_number(Blockchain.BTC)
        )
        btc_tx_params = BitcoinTxParams(
            sources=[
                BitcoinTransactionSource(
                    txid=bytes.fromhex("0ab2271ac67533458ee3fe02881062489f9839193f94145bade64069712ef007"), vout=0
                )
            ],
            destinations=[],
        )
        self.assertTrue(self._test_validate_helper(Blockchain.BTC, btc_tx_params))


if __name__ == "__main__":
    unittest.main()
