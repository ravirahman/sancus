import logging
import os
import subprocess
import tempfile
from argparse import ArgumentParser
from datetime import timedelta
from decimal import Decimal
from threading import Event

import requests
from auditgen.config import AuditGenConfig
from auditgen.generate_audit import AuditGen
from dotenv import load_dotenv
from web3.middleware.geth_poa import geth_poa_middleware
from web3.providers.rpc import HTTPProvider

from auditor.auditor import Auditor
from auditor.config import AuditorConfig
from auditor.config import WebauthnConfig as AuditorWebauthnConfig
from backend.backend import Backend
from backend.config import BackendConfig, BTCConfig, ETHConfig, JWTConfig
from backend.config import WebauthnConfig as BackendWebauthnConfig
from common.config import (
    BTCProxyConfig,
    GRPCConfig,
    GRPCServerConfig,
    GRPCWebProxyConfig,
    IPFSConfig,
    SQLAlchemyConfig,
    W3Config,
)
from common.constants import Currency
from common.utils.server_exception_interceptor import ServerExceptionInterceptor

ETH_DOTENV_PATH = os.path.join(os.path.dirname(__file__), "infra", "output", "eth.env")
ETH_CONTRACTS_DOTENV_PATH = os.path.join(os.path.dirname(__file__), "infra", "output", "eth_contracts.env")

assert os.path.exists(ETH_DOTENV_PATH)
assert os.path.exists(ETH_CONTRACTS_DOTENV_PATH)
load_dotenv(ETH_DOTENV_PATH)
load_dotenv(ETH_CONTRACTS_DOTENV_PATH)

W3_MAX_WORKERS = 10


def _get_w3_provider() -> HTTPProvider:
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=W3_MAX_WORKERS,
        pool_maxsize=W3_MAX_WORKERS,
        max_retries=5,
        pool_block=True,
    )
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return HTTPProvider("http://localhost:8545", session=session, request_kwargs={"timeout": 60})


PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), "sancus.key")
CERTIFICATE_FILE = os.path.join(os.path.dirname(__file__), "sancus.crt")
PEM_FILE = os.path.join(os.path.dirname(__file__), "sancus.pem")

W3_CONFIG = W3Config(
    provider=_get_w3_provider(),
    middlewares=(geth_poa_middleware,),
    chain_id=58,
    start_block_number=int(os.environ["ETH_CONTRACTS_BLOCK_NUMBER"]),
    stablecoin_to_erc20_contract_address={
        Currency.GUSD: os.environ["GUSD_CONTRACT_ADDRESS"],
    },
    max_workers=W3_MAX_WORKERS,
)

BTC_PROXY_CONFIG = BTCProxyConfig(
    btc_service_url="http://bitcoin:password@localhost:18444",
    btc_node_type="regtest",
    start_block_number=1,
    max_workers=10,
)

BACKEND_GRPC_CONFIG = GRPCConfig(
    host="localhost:50051",
    root_certificates=CERTIFICATE_FILE,
    certificate_chain=CERTIFICATE_FILE,
    max_workers=10,
)


AUDITOR_GRPC_CONFIG = GRPCConfig(
    host="localhost:50052",
    root_certificates=CERTIFICATE_FILE,  # in a real setup, the auditor would have a different key than the backend
    certificate_chain=CERTIFICATE_FILE,
    max_workers=10,
)

JWT_CONFIG = JWTConfig(
    private_key_file=PRIVATE_KEY_FILE,
    public_key_file=PEM_FILE,
    auth_duration=timedelta(days=30),
    # sometimes, gemini has really old rates on the ethbtc market
    rate_duration=timedelta(minutes=15),
    issuer="http://localhost:3000",
    algorithm="RS256",
)

BACKEND_WEBAUTHN_CONFIG = BackendWebauthnConfig(
    rp_id="localhost",
    origin="http://localhost:3000",
    rp_name="localhost",
    challenge_duration=timedelta(minutes=5),
    timeout=timedelta(minutes=5),
)

IPFS_CONFIG = IPFSConfig(
    chunk_size=1024,
    ipfs_host_uri="/ip4/127.0.0.1/tcp/5001",
)


def _configure_logging() -> None:
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logging.getLogger("auditor").setLevel(logging.INFO)
    logging.getLogger("backend").setLevel(logging.INFO)
    logging.getLogger("auditgen").setLevel(logging.INFO)
    logging.getLogger("common").setLevel(logging.INFO)
    logging.getLogger("grpc").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)


def auditor() -> None:
    _configure_logging()
    with tempfile.TemporaryDirectory() as audit_folder:
        config = AuditorConfig(
            sqlalchemy_config=SQLAlchemyConfig(
                uri="mysql+pymysql://root:password@localhost:3306/auditor",
                echo=False,
                pool_size=10,
                max_overflow=10,
            ),
            webauthn_config=AuditorWebauthnConfig(
                rp_id="localhost",
                rp_name="localhost",
                origin="http://localhost:3000",
            ),
            grpc_server_config=GRPCServerConfig(
                grpc_config=AUDITOR_GRPC_CONFIG,
                grpc_web_proxy_config=GRPCWebProxyConfig(
                    grpc_config=AUDITOR_GRPC_CONFIG,
                    server_tls_cert_file=CERTIFICATE_FILE,
                    server_tls_key_file=PRIVATE_KEY_FILE,
                    server_http_tls_port=8444,
                    server_bind_address="0.0.0.0",
                    allow_all_origins=True,
                    use_websockets=True,
                ),
                tls_key_file=PRIVATE_KEY_FILE,
                interceptors=(ServerExceptionInterceptor(),),
            ),
            w3_config=W3_CONFIG,
            ipfs_config=IPFS_CONFIG,
            btc_proxy_config=BTC_PROXY_CONFIG,
            audit_folder=audit_folder,
            audit_smart_contract_address=os.environ["AUDIT_PUBLISHER_CONTRACT_ADDRESS"],
            acceptable_exchange_rate_epsilon=Decimal("0.01"),
        )
        try:
            with Auditor(config):
                print("Started auditor. Press ctrl-c to stop...")
                Event().wait()
        except KeyboardInterrupt:
            pass


BTC_CONFIG = BTCConfig(
    proxy_config=BTC_PROXY_CONFIG,
    num_confirmations=6,
    rebroadcast_interval=timedelta(minutes=10),
    transaction_timeout=timedelta(minutes=10),
)


ETH_CONFIG = ETHConfig(
    w3_config=W3_CONFIG,
    num_confirmations=6,
    rebroadcast_interval=timedelta(minutes=10),
    transaction_timeout=timedelta(minutes=10),
    default_address=os.environ["ETH_MAIN_ADDRESS"],
)


def backend() -> None:
    _configure_logging()
    config = BackendConfig(
        sqlalchemy_config=SQLAlchemyConfig(
            uri="mysql+pymysql://root:password@localhost:3306/backend",
            echo=False,
            pool_size=BTC_CONFIG.proxy_config.max_workers
            + ETH_CONFIG.w3_config.max_workers
            + BACKEND_GRPC_CONFIG.max_workers,
            max_overflow=10,
        ),
        grpc_server_config=GRPCServerConfig(
            grpc_config=BACKEND_GRPC_CONFIG,
            tls_key_file=PRIVATE_KEY_FILE,
            grpc_web_proxy_config=GRPCWebProxyConfig(
                grpc_config=BACKEND_GRPC_CONFIG,
                server_tls_cert_file=CERTIFICATE_FILE,
                server_tls_key_file=PRIVATE_KEY_FILE,
                server_http_tls_port=8443,
                server_bind_address="0.0.0.0",
                allow_all_origins=True,
                use_websockets=True,
            ),
            interceptors=(ServerExceptionInterceptor(),),
        ),
        jwt_config=JWT_CONFIG,
        webauthn_config=BACKEND_WEBAUTHN_CONFIG,
        eth_config=ETH_CONFIG,
        btc_config=BTC_CONFIG,
        deposit_faucet_amounts={
            Currency.GUSD: Decimal("100"),
            Currency.ETH: Decimal("1"),
            Currency.BTC: Decimal("0.5"),
        },
        exchange_rate_spread=Decimal("1.02"),
        account_anonymity_set_size=5,
        deposit_key_decoy_set_size=5,
    )
    try:
        with Backend(config):
            print("Started backend. Press ctrl-c to stop...")
            Event().wait()
    except KeyboardInterrupt:
        pass


def auditgen() -> None:
    _configure_logging()
    config = AuditGenConfig(
        jwt_config=JWT_CONFIG,
        audit_smart_contract_address=os.environ["AUDIT_PUBLISHER_CONTRACT_ADDRESS"],
        audit_publisher_address=os.environ["ETH_CONTRACTS_OWNER"],
        grpc_config=BACKEND_GRPC_CONFIG,
        ipfs_config=IPFS_CONFIG,
        w3_config=W3_CONFIG,
    )
    with AuditGen(config) as audit_gen:
        with tempfile.TemporaryDirectory() as tempdir:
            audit_gen.generate_audit(tempdir)
            audit_gen.publish_audit(tempdir)


def client() -> None:
    with subprocess.Popen(
        [
            "yarn",
            "start",
        ],
        cwd=os.path.join(os.path.dirname(__file__), "client"),
        universal_newlines=True,
    ) as client_proc:
        try:
            Event().wait()
        except KeyboardInterrupt:
            client_proc.kill()


def main() -> None:
    parser = ArgumentParser(description="Sancus")
    parser.add_argument(
        "service",
        type=str,
        help="Service to run",
        choices=["backend", "auditor", "auditgen", "client"],
    )
    args = parser.parse_args()
    service = args.service
    if service == "backend":
        backend()
        return
    if service == "auditor":
        auditor()
        return
    if service == "client":
        client()
        return
    if service == "auditgen":
        auditgen()
        return


if __name__ == "__main__":
    main()
