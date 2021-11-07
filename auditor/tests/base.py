import contextlib
import logging
import tempfile
import unittest

import grpc
from common.constants import SECP256K1_GENERATOR, SECP256K1_ORDER, Blockchain
from common.utils.grpc_channel import make_grpc_channel
from common.utils.uuid import generate_uuid4
from common.utils.zk.bit_commitment import generate_bit_commitment
from common.utils.zk.key_permutation import permute_public_key

from auditor.auditor import Auditor
from auditor.config import AuditorConfig
from auditor.sql.base import Base
from tests.fixtures import generate_mock_config


class BaseAuditorTestCase(unittest.TestCase):
    tempdir: "tempfile.TemporaryDirectory[str]"
    auditor: Auditor
    channel: grpc.Channel
    config: AuditorConfig

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig()
        logging.getLogger("auditor").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
        logging.getLogger("tests").setLevel(logging.DEBUG)
        cls.tempdir = tempfile.TemporaryDirectory()
        config = generate_mock_config(cls.tempdir.name)
        cls.auditor = Auditor(config)
        # setting stopped so we don't run the background loop
        cls.auditor.stopped = True
        cls.auditor.audit_listener.stopped = True
        cls.auditor.start()
        cls.channel = make_grpc_channel(config.grpc_server_config.grpc_config)
        cls.config = config

    def setUp(self) -> None:
        self.auditor.eth_client.start_block_number = self.auditor.blockchain_client.get_latest_block_number_from_chain(
            Blockchain.ETH
        )
        self.eth_start_block = self.auditor.blockchain_client.get_start_block_number(Blockchain.ETH)
        self.auditor.btc_client.start_block_number = self.auditor.blockchain_client.get_latest_block_number_from_chain(
            Blockchain.BTC
        )
        self.btc_start_block = self.auditor.blockchain_client.get_start_block_number(Blockchain.BTC)

        self.auditor.initialize()

        self.key_uuid = generate_uuid4()
        self.private_key_bn = SECP256K1_ORDER.random()
        public_key = self.private_key_bn * SECP256K1_GENERATOR
        k = SECP256K1_ORDER.random()
        permuted_public_key, nizk = permute_public_key(public_key, k)

        ownership_commitment, ownership_nizk = generate_bit_commitment(
            True, SECP256K1_ORDER.random(), G=SECP256K1_GENERATOR
        )
        with self.auditor.sessionmaker() as session:
            self.auditor.key_client.track_deposit_key(
                session,
                self.key_uuid,
                public_key,
                permuted_public_key,
                nizk,
                audit_version=1,
                ownership_commitment=ownership_commitment,
                ownership_nizk=ownership_nizk,
            )
            session.commit()

    def tearDown(self) -> None:
        with contextlib.closing(self.auditor.sqlalchemy_engine.connect()) as con:
            trans = con.begin()
            for table in reversed(Base.metadata.sorted_tables):
                con.execute(table.delete())
            trans.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.auditor.stop()
        cls.channel.close()
        cls.tempdir.cleanup()
