import logging
from types import TracebackType
from typing import Optional, Type

import sqlalchemy.orm
from common.utils.grpc_server import GRPCServer
from common.utils.ipfs_client import IPFSClient
from common.utils.sqlalchemy_engine import make_sqlalchemy_engine

from auditor.audit_listener import AuditListener
from auditor.audit_processor import AuditProcessor
from auditor.config import AuditorConfig
from auditor.service import AuditorService
from auditor.sql.base import Base
from auditor.utils.blockchain_client.btc import BTCClient
from auditor.utils.blockchain_client.client import BlockchainClient
from auditor.utils.blockchain_client.eth import ETHClient
from auditor.utils.key_client import KeyClient
from auditor.utils.marketdata_client import MarketdataClient
from auditor.utils.webauthn_client import WebauthnClient

LOGGER = logging.getLogger(__name__)


class Auditor:
    def __init__(self, config: AuditorConfig) -> None:
        self.sqlalchemy_engine = make_sqlalchemy_engine(config.sqlalchemy_config)
        Base.metadata.create_all(self.sqlalchemy_engine)
        self.sessionmaker = sqlalchemy.orm.sessionmaker(bind=self.sqlalchemy_engine)
        self.eth_client = ETHClient(config.w3_config, self.sessionmaker)
        self.btc_client = BTCClient(self.sessionmaker, config.btc_proxy_config)
        self.marketdata_client = MarketdataClient()
        self.blockchain_client = BlockchainClient(self.eth_client, self.btc_client, self.sessionmaker)
        self.key_client = KeyClient(self.blockchain_client)
        self.webauthn_client = WebauthnClient(config.webauthn_config)
        self.audit_processor = AuditProcessor(
            self.key_client,
            self.webauthn_client,
            self.blockchain_client,
            self.marketdata_client,
            self.sessionmaker,
            config.acceptable_exchange_rate_epsilon,
            config.audit_folder,
        )
        self.ipfs_client = IPFSClient(config.ipfs_config)
        self.audit_listener = AuditListener(
            self.ipfs_client, config.w3_config, config.audit_smart_contract_address, self.audit_processor
        )
        self.stopped = False
        self.grpc_server = GRPCServer(config.grpc_server_config)
        AuditorService(self.sessionmaker, config, self.grpc_server.grpc_server, self.blockchain_client)

    def initialize(self) -> None:
        self.blockchain_client.initialize()

    def start(self) -> None:
        self.initialize()
        self.grpc_server.start()
        self.audit_listener.start()

    def __enter__(self) -> "Auditor":
        self.start()
        return self

    def stop(self) -> None:
        self.stopped = True
        self.audit_listener.stop()
        self.ipfs_client.close()
        self.grpc_server.stop()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.stop()
