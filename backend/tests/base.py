import contextlib
import logging
import tempfile
import unittest

import grpc
from common.utils.grpc_channel import make_grpc_channel
from common.utils.soft_webauthn_client import SoftWebauthnClient
from common.utils.uuid import bytes_to_uuid

from backend.backend import Backend
from backend.config import BackendConfig
from backend.sql.base import Base
from backend.sql.user import User
from tests.fixtures import (
    MOCK_USER_UUID,
    generate_mock_backend_config,
    get_latest_btc_block_number,
    get_latest_eth_block_number,
    get_mock_jwt,
)


class BaseBackendTestCase(unittest.TestCase):
    tempdir: "tempfile.TemporaryDirectory[str]"
    backend: Backend
    channel: grpc.Channel
    config: BackendConfig

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig()
        logging.getLogger("backend").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
        logging.getLogger("tests").setLevel(logging.DEBUG)
        cls.tempdir = tempfile.TemporaryDirectory()
        config = generate_mock_backend_config(
            cls.tempdir.name,
            eth_start_block_number=get_latest_eth_block_number(),
            btc_start_block_number=get_latest_btc_block_number(),
        )
        cls.backend = Backend(config)
        cls.backend.stopped = True  # setting stopped so we don't run the background loop
        cls.backend.start()
        cls.channel = make_grpc_channel(
            config.grpc_server_config.grpc_config,
            get_mock_jwt(MOCK_USER_UUID),
        )
        cls.config = config

    def setUp(self) -> None:
        # repopulate the database
        self.backend.marketdata_client.update_quotes()
        self.soft_webauthn = SoftWebauthnClient(origin=self.config.webauthn_config.origin)
        # add a key for the mock user
        with self.backend.sessionmaker() as session:
            user = User(username="test_user", user_uuid=MOCK_USER_UUID)
            session.add(user)
            session.commit()
            challenge_request, credential_request = self.backend.webauthn_client.build_create_credential_request(
                session, user.user_uuid, user.username
            )
            session.commit()
            challenge_uuid = bytes_to_uuid(challenge_request.nonce)
            response = self.soft_webauthn.create_credential(credential_request=credential_request)
            self.backend.webauthn_client.validate_attestation_response(session, challenge_uuid, response)
            session.commit()

    def tearDown(self) -> None:
        with contextlib.closing(self.backend.sqlalchemy_engine.connect()) as con:
            trans = con.begin()
            for table in reversed(Base.metadata.sorted_tables):
                con.execute(table.delete())
            trans.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.backend.stop()
        cls.channel.close()
        cls.tempdir.cleanup()
