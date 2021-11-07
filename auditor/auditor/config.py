from dataclasses import dataclass
from decimal import Decimal

from common.config import (
    BTCProxyConfig,
    GRPCServerConfig,
    IPFSConfig,
    SQLAlchemyConfig,
    W3Config,
)


@dataclass(frozen=True)
class WebauthnConfig:
    rp_name: str
    rp_id: str
    origin: str


@dataclass(frozen=True)
class AuditorConfig:
    sqlalchemy_config: SQLAlchemyConfig
    grpc_server_config: GRPCServerConfig
    btc_proxy_config: BTCProxyConfig
    webauthn_config: WebauthnConfig
    w3_config: W3Config
    audit_folder: str
    ipfs_config: IPFSConfig
    audit_smart_contract_address: str
    acceptable_exchange_rate_epsilon: Decimal
