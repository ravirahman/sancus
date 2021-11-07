from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Mapping, Optional, Sequence, Union

import web3
from web3.providers.base import BaseProvider

from common.constants import Currency

if TYPE_CHECKING:
    from typing import Any

    import grpc


@dataclass(frozen=True)
class IPFSConfig:
    ipfs_host_uri: str
    chunk_size: int


@dataclass(frozen=True)
class GRPCConfig:
    host: str
    max_workers: int
    root_certificates: Optional[str] = None
    certificate_chain: Optional[str] = None


@dataclass(frozen=True)
class GRPCWebProxyConfig:
    grpc_config: GRPCConfig
    server_tls_cert_file: str
    server_tls_key_file: str
    server_http_tls_port: int
    server_bind_address: str
    allow_all_origins: bool = False
    allowed_origins: Optional[Sequence[str]] = None
    allowed_headers: Optional[Sequence[str]] = None
    # ("authorization", "access-control-request-headers", "acecss-control-request-method",
    #  "origin", "referer")
    use_websockets: bool = False


@dataclass(frozen=True)
class GRPCServerConfig:  # type: ignore[misc]
    grpc_config: GRPCConfig
    tls_key_file: Optional[str] = None  # not needed if underlying grpc config host is a UDS
    interceptors: "Sequence[grpc.ServerInterceptor[Any, Any]]" = tuple()  # type: ignore[misc]
    grpc_web_proxy_config: Optional[GRPCWebProxyConfig] = None


@dataclass(frozen=True)
class W3Config:
    provider: BaseProvider
    chain_id: int
    start_block_number: int
    stablecoin_to_erc20_contract_address: Mapping[Currency, str]
    max_workers: int
    middlewares: Sequence[web3.types.Middleware] = tuple()


@dataclass(frozen=True)
class BTCProxyConfig:
    btc_service_url: str
    btc_node_type: Union[Literal["regtest"], Literal["testnet"], Literal["mainnet"]]
    start_block_number: int
    max_workers: int


@dataclass(frozen=True)
class SQLAlchemyConfig:
    uri: str
    echo: bool
    pool_size: int
    max_overflow: int
