from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Mapping, Optional

from common.config import BTCProxyConfig, GRPCServerConfig, SQLAlchemyConfig, W3Config
from common.constants import Currency


@dataclass(frozen=True)
class WebauthnConfig:
    rp_name: str
    rp_id: str
    timeout: timedelta
    origin: str
    challenge_duration: timedelta


@dataclass(frozen=True)
class JWTConfig:
    private_key_file: str
    public_key_file: str
    auth_duration: timedelta
    rate_duration: timedelta
    issuer: str
    algorithm: str


@dataclass(frozen=True)
class ETHConfig:
    w3_config: W3Config
    num_confirmations: int
    default_address: str
    rebroadcast_interval: timedelta
    transaction_timeout: timedelta


@dataclass(frozen=True)
class BTCConfig:
    proxy_config: BTCProxyConfig
    num_confirmations: int
    rebroadcast_interval: timedelta
    transaction_timeout: timedelta


@dataclass(frozen=True)
class BackendConfig:
    sqlalchemy_config: SQLAlchemyConfig
    jwt_config: JWTConfig
    webauthn_config: WebauthnConfig
    grpc_server_config: GRPCServerConfig
    eth_config: ETHConfig
    btc_config: BTCConfig
    exchange_rate_spread: Decimal
    account_anonymity_set_size: int
    deposit_key_decoy_set_size: int
    deposit_faucet_amounts: Optional[Mapping[Currency, Decimal]] = None
