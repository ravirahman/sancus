import logging
import os
from decimal import Decimal
from threading import Event

from auditor.auditor import Auditor
from auditor.config import AuditorConfig, WebauthnConfig
from common.config import GRPCConfig, GRPCServerConfig, SQLAlchemyConfig
from common.utils.latency_interceptor import LatencyInterceptor
from common.utils.server_exception_interceptor import ServerExceptionInterceptor

from utils.config import BTC_PROXY_CONFIG, IPFS_CONFIG, W3_CONFIG, configure_logging
from utils.constants import WEBAUTHN_ORIGIN

LOGGER = logging.getLogger(__name__)

AUDITOR_GRPC_CONFIG = GRPCConfig(
    host=os.environ["AUDITOR_GRPC_SOCKFILE"],
    max_workers=10,
)


def auditor() -> None:
    configure_logging(os.environ["AUDITOR_LOG_FILE"])

    config = AuditorConfig(
        sqlalchemy_config=SQLAlchemyConfig(
            uri=os.environ["AUDITOR_DB"],
            echo=False,
            pool_size=10,  # TODO
            max_overflow=10,  # TODO
        ),
        webauthn_config=WebauthnConfig(
            rp_id="localhost",
            rp_name="localhost",
            origin=WEBAUTHN_ORIGIN,
        ),
        grpc_server_config=GRPCServerConfig(
            grpc_config=AUDITOR_GRPC_CONFIG,
            interceptors=(
                LatencyInterceptor(),
                ServerExceptionInterceptor(),
            ),
        ),
        w3_config=W3_CONFIG,
        ipfs_config=IPFS_CONFIG,
        btc_proxy_config=BTC_PROXY_CONFIG,
        audit_folder=os.environ["AUDITOR_FOLDER"],
        audit_smart_contract_address=os.environ["AUDIT_PUBLISHER_CONTRACT_ADDRESS"],
        acceptable_exchange_rate_epsilon=Decimal(os.environ["EXCHANGE_RATE_EPSILON"]),
    )
    with Auditor(config):
        print("Started auditor")
        Event().wait()


if __name__ == "__main__":
    auditor()
