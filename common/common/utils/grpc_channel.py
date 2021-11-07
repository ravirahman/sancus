from typing import Optional

import grpc

from common.config import GRPCConfig
from common.utils.client_exception_interceptor import ClientExceptionInterceptor


class AuthMetadataPlugin(grpc.AuthMetadataPlugin):
    def __init__(self, authorization_jwt: str) -> None:
        super().__init__()
        self._authorization_jwt = authorization_jwt

    def __call__(self, context: grpc.AuthMetadataContext, callback: grpc.AuthMetadataPluginCallback) -> None:
        metadata = (("authorization", self._authorization_jwt),)
        callback(metadata, None)


def make_grpc_channel(grpc_config: GRPCConfig, jwt: Optional[str] = None) -> grpc.Channel:
    if grpc_config.host.startswith("unix://"):
        channel_credentials = grpc.local_channel_credentials(grpc.LocalConnectionType.UDS)
    else:
        if grpc_config.root_certificates is None:
            root_certificates: Optional[bytes] = None
        else:
            with open(grpc_config.root_certificates, "rb") as f:
                root_certificates = f.read()

        # if grpc_config.certificate_chain is None:
        #     certificate_chain: Optional[bytes] = None
        # else:
        #     with open(grpc_config.certificate_chain, "rb") as f:
        #         certificate_chain = f.read()

        channel_credentials = grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
        )
    if jwt is None:
        composite_credentials: grpc.ChannelCredentials = channel_credentials
    else:
        composite_credentials = grpc.composite_channel_credentials(  # type: ignore[assignment]
            channel_credentials,
            grpc.metadata_call_credentials(
                AuthMetadataPlugin(jwt),
                name="auth_metadata_plugin",
            ),
        )
    return grpc.intercept_channel(
        grpc.secure_channel(grpc_config.host, composite_credentials),
        ClientExceptionInterceptor(),
    )
