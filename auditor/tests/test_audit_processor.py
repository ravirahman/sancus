import os
import unittest
from unittest.mock import patch

import sqlalchemy

from auditor.audit_processor import AuditProcessor
from auditor.auditor import Auditor
from auditor.config import AuditorConfig
from auditor.utils.blockchain_client.client import BlockchainClient
from auditor.utils.key_client import KeyClient
from auditor.utils.marketdata_client import MarketdataClient
from auditor.utils.webauthn_client import WebauthnClient
from tests.base import BaseAuditorTestCase
from tests.fixtures import (
    mock_convert_to_base_currency_commitment,
    mock_process_new_block,
    mock_return_none,
    mock_return_true,
    mock_return_zero,
)


@patch.object(AuditProcessor, "process_new_blocks", mock_process_new_block)
@patch.object(AuditProcessor, "validate_block_timestamps", mock_return_none)
@patch.object(BlockchainClient, "get_latest_block_number_from_chain", lambda _, __: 1_000_000)
@patch.object(BlockchainClient, "validate_tx_in_chain", mock_return_true)
@patch.object(BlockchainClient, "get_block_metadata_from_chain", mock_return_none)
@patch.object(BlockchainClient, "get_balance_from_chain", mock_return_zero)
class TestAuditProcessor(BaseAuditorTestCase):
    auditor: Auditor
    sessionmaker: sqlalchemy.orm.sessionmaker
    key_client: KeyClient
    webauthn_client: WebauthnClient
    blockchain_client: BlockchainClient
    marketdata_client: MarketdataClient
    config: AuditorConfig

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.key_client = cls.auditor.key_client
        cls.webauthn_client = cls.auditor.webauthn_client
        cls.blockchain_client = cls.auditor.blockchain_client
        cls.marketdata_client = cls.auditor.marketdata_client
        cls.config = cls.config
        cls.sessionmaker = cls.auditor.sessionmaker

    def test_audit_processor_one(self) -> None:
        self.auditor.audit_processor.process_audit(os.path.join(os.path.dirname(__file__), "audit_3.tgz"))

    # mocking the validation since the amounts are neither in the database nor on the blockchain since they
    # were generated offline
    # so, take the amounts in the currency conversion commitment as fact
    @patch("auditor.audit_processor.verify_key_amount_commitment", mock_return_none)
    @patch.object(BlockchainClient, "get_cumulative_deposits", mock_return_zero)
    @patch.object(AuditProcessor, "_convert_to_base_currency_commitment", mock_convert_to_base_currency_commitment)
    def test_audit_processor_both(self) -> None:  # type: ignore[misc]
        self.auditor.audit_processor.process_audit(os.path.join(os.path.dirname(__file__), "audit_1.tgz"))
        self.auditor.audit_processor.process_audit(os.path.join(os.path.dirname(__file__), "audit_2.tgz"))


if __name__ == "__main__":
    unittest.main()
