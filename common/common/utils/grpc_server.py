import logging
from concurrent.futures import ThreadPoolExecutor
from types import TracebackType
from typing import Optional, Type

import grpc
from grpc_health.v1.health import HealthServicer
from grpc_health.v1.health_pb2 import HealthCheckResponse
from grpc_health.v1.health_pb2_grpc import add_HealthServicer_to_server

from common.config import GRPCServerConfig
from common.utils.grpc_web_proxy import GRPCWebProxy

LOGGER = logging.getLogger(__name__)


class GRPCServer:
    def __init__(self, config: GRPCServerConfig) -> None:
        self.grpc_server = grpc.server(
            ThreadPoolExecutor(config.grpc_config.max_workers),
            interceptors=config.interceptors,  # type: ignore[arg-type]
        )
        self._health_servicer = HealthServicer()
        self._grpc_web_proxy: Optional[GRPCWebProxy] = None
        if config.grpc_web_proxy_config is not None:
            self._grpc_web_proxy = GRPCWebProxy(config.grpc_web_proxy_config)
        add_HealthServicer_to_server(self._health_servicer, self.grpc_server)
        if config.grpc_config.host.startswith("unix://"):
            server_credentials = grpc.local_server_credentials(local_connect_type=grpc.LocalConnectionType.UDS)
        else:
            assert config.tls_key_file is not None
            with open(config.tls_key_file, "rb") as f:
                tls_key = f.read()
            assert config.grpc_config.certificate_chain is not None
            with open(config.grpc_config.certificate_chain, "rb") as f:
                tls_chain = f.read()
            server_credentials = grpc.ssl_server_credentials([(tls_key, tls_chain)])
        self.grpc_server.add_secure_port(config.grpc_config.host, server_credentials)

    def start(self) -> None:
        LOGGER.info("Starting the grpc server")
        self.grpc_server.start()
        if self._grpc_web_proxy is not None:
            self._grpc_web_proxy.start()
        for (
            handler
        ) in self.grpc_server._state.generic_handlers:  # type: ignore[attr-defined]  # pylint: disable=protected-access
            service_name = handler.service_name()
            LOGGER.info("Setting service %s health status to serving", service_name)
            self._health_servicer.set(handler.service_name(), HealthCheckResponse.SERVING)

    def __enter__(self) -> "GRPCServer":
        self.start()
        return self

    def stop(self) -> None:
        if self._grpc_web_proxy is not None:
            LOGGER.info("Stopping the grpc web proxy")
            self._grpc_web_proxy.stop()
        LOGGER.info("Stopping the grpc server")
        self.grpc_server.stop(grace=None)

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.stop()
