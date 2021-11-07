import logging
import os
from datetime import timedelta

from backend.config import JWTConfig, WebauthnConfig
from common.config import BTCProxyConfig, GRPCConfig, IPFSConfig, W3Config
from common.constants import Currency
from web3.middleware.geth_poa import geth_poa_middleware

from utils.constants import (
    BTC_HOST,
    IPFS_HOST,
    MAX_BTC_WORKERS,
    MAX_ETH_WORKERS,
    WEBAUTHN_ORIGIN,
    get_w3_provider,
)


def configure_logging(logging_file: str) -> None:
    logging.basicConfig(
        filename=logging_file,
        filemode="x",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logging.getLogger("auditor").setLevel(logging.INFO)
    logging.getLogger("backend").setLevel(logging.INFO)
    logging.getLogger("auditgen").setLevel(logging.INFO)
    logging.getLogger("common").setLevel(logging.INFO)
    logging.getLogger("grpc").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)


W3_CONFIG = W3Config(
    provider=get_w3_provider(),
    middlewares=(geth_poa_middleware,),
    chain_id=58,
    start_block_number=int(os.environ["ETH_START_BLOCK_NUMBER"]),
    stablecoin_to_erc20_contract_address={
        Currency.GUSD: os.environ["GUSD_CONTRACT_ADDRESS"],
    },
    max_workers=MAX_ETH_WORKERS,
)


PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "sancus.key")
CERTIFICATE_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "sancus.crt")
PEM_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "sancus.pem")

BACKEND_GRPC_CONFIG = GRPCConfig(
    host=os.environ["BACKEND_GRPC_SOCKFILE"],
    max_workers=10,
)

BACKEND_JWT_CONFIG = JWTConfig(
    private_key_file=PRIVATE_KEY_FILE,
    public_key_file=PEM_FILE,
    auth_duration=timedelta(days=30),
    # sometimes, gemini has really old rates on the ethbtc market
    rate_duration=timedelta(minutes=15),
    issuer="http://localhost:3000",
    algorithm="RS256",
)

BACKEND_WEBAUTHN_CONFIG = WebauthnConfig(
    rp_id="localhost",
    origin=WEBAUTHN_ORIGIN,
    rp_name="localhost",
    challenge_duration=timedelta(minutes=5),
    timeout=timedelta(minutes=5),
)

IPFS_CONFIG = IPFSConfig(
    chunk_size=1024,
    ipfs_host_uri=IPFS_HOST,
)

BTC_PROXY_CONFIG = BTCProxyConfig(
    btc_service_url=BTC_HOST,
    btc_node_type="regtest",
    start_block_number=int(os.environ["BTC_START_BLOCK_NUMBER"]),
    max_workers=MAX_BTC_WORKERS,
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
