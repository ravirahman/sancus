import argparse
import os

from auditgen.config import AuditGenConfig
from auditgen.generate_audit import AuditGen

from utils.config import (
    BACKEND_GRPC_CONFIG,
    BACKEND_JWT_CONFIG,
    IPFS_CONFIG,
    W3_CONFIG,
    configure_logging,
)


def auditgen() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output_directory",
        type=str,
        required=True,
        help="Output directory where audit should be created",
    )
    args = parser.parse_args()
    output_directory = args.output_directory
    configure_logging(os.path.join(output_directory, "auditgen.log"))
    config = AuditGenConfig(
        jwt_config=BACKEND_JWT_CONFIG,
        audit_smart_contract_address=os.environ["AUDIT_PUBLISHER_CONTRACT_ADDRESS"],
        audit_publisher_address=os.environ["ETH_CONTRACTS_OWNER"],
        grpc_config=BACKEND_GRPC_CONFIG,
        ipfs_config=IPFS_CONFIG,
        w3_config=W3_CONFIG,
    )
    with AuditGen(config) as audit_gen:
        audit_gen.generate_audit(output_directory)
        audit_gen.publish_audit(output_directory)


if __name__ == "__main__":
    auditgen()
