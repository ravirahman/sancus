from dataclasses import dataclass

from common.config import GRPCConfig, IPFSConfig, W3Config

from backend.config import JWTConfig


@dataclass(frozen=True)
class AuditGenConfig:
    audit_smart_contract_address: str
    audit_publisher_address: str
    jwt_config: JWTConfig
    grpc_config: GRPCConfig
    ipfs_config: IPFSConfig
    w3_config: W3Config
