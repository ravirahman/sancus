import logging
import os
from datetime import timedelta
from decimal import Decimal
from threading import Event

from backend.backend import Backend
from backend.config import BackendConfig, BTCConfig, ETHConfig
from common.config import GRPCServerConfig, SQLAlchemyConfig
from common.utils.latency_interceptor import LatencyInterceptor
from common.utils.server_exception_interceptor import ServerExceptionInterceptor

from utils.config import (
    BACKEND_GRPC_CONFIG,
    BACKEND_JWT_CONFIG,
    BACKEND_WEBAUTHN_CONFIG,
    BTC_PROXY_CONFIG,
    W3_CONFIG,
    configure_logging,
)

LOGGER = logging.getLogger(__name__)


BTC_CONFIG = BTCConfig(
    proxy_config=BTC_PROXY_CONFIG,
    num_confirmations=1,  # effectively disable confirmations
    rebroadcast_interval=timedelta(minutes=10),  # rebroadcast aggressively, but don't overload the node
    transaction_timeout=timedelta(minutes=2),  # if we don't sign a transaction within 2 minutes, cancel it
)


ETH_CONFIG = ETHConfig(
    w3_config=W3_CONFIG,
    num_confirmations=1,  # effectively disable confirmations
    rebroadcast_interval=timedelta(minutes=10),  # rebroadcast aggressively, but don't overload the node
    transaction_timeout=timedelta(minutes=2),  # if we don't sign a transaction within 2 minutes, cancel it
    default_address=os.environ["ETH_MAIN_ADDRESS"],
)


def backend() -> None:
    configure_logging(os.environ["BACKEND_LOG_FILE"])
    config = BackendConfig(
        sqlalchemy_config=SQLAlchemyConfig(
            uri=os.environ["BACKEND_DB"],
            echo=False,
            pool_size=10,  # TODO
            max_overflow=10,  # TODO
        ),
        grpc_server_config=GRPCServerConfig(
            grpc_config=BACKEND_GRPC_CONFIG,
            interceptors=(
                LatencyInterceptor(),
                ServerExceptionInterceptor(),
            ),
        ),
        jwt_config=BACKEND_JWT_CONFIG,
        webauthn_config=BACKEND_WEBAUTHN_CONFIG,
        eth_config=ETH_CONFIG,
        btc_config=BTC_CONFIG,
        account_anonymity_set_size=int(os.environ["ACCOUNT_ANONYMITY_SET_SIZE"]),
        exchange_rate_spread=Decimal("1"),
        deposit_key_decoy_set_size=int(os.environ["DEPOSIT_KEY_DECOY_SET_SIZE"]),
    )
    with Backend(config):
        LOGGER.info("Started backend")
        Event().wait()


if __name__ == "__main__":
    backend()
