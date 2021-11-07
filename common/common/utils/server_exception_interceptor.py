import logging
import queue
import socket
from abc import ABC
from typing import TYPE_CHECKING, Generic, TypeVar

import grpc
import requests
from google.protobuf.message import Message
from sqlalchemy.exc import OperationalError

TRequest = TypeVar("TRequest", bound=Message)
TResponse = TypeVar("TResponse", bound=Message)

if TYPE_CHECKING:
    from typing import Callable, Optional  # pylint: disable=ungrouped-imports

    class ServerInterceptor(grpc.ServerInterceptor[TRequest, TResponse]):  # pylint: disable=unsubscriptable-object
        pass


else:

    class ServerInterceptor(Generic[TRequest, TResponse], grpc.ServerInterceptor, ABC):
        pass


LOGGER = logging.getLogger(__name__)


class ServerExceptionInterceptor(ServerInterceptor[TRequest, TResponse]):
    @staticmethod
    def intercept_service(  # type: ignore[override]
        continuation: "Callable[[grpc.HandlerCallDetails], Optional[grpc.RpcMethodHandler[TRequest, TResponse]]]",
        handler_call_details: grpc.HandlerCallDetails,
    ) -> "Optional[grpc.RpcMethodHandler[TRequest, TResponse]]":
        rpc_method_handler = continuation(handler_call_details)
        if rpc_method_handler is None:
            return None
        if rpc_method_handler.request_streaming:
            return rpc_method_handler
        if rpc_method_handler.response_streaming:
            return rpc_method_handler

        def behavior(request: TRequest, context: grpc.ServicerContext) -> TResponse:
            assert rpc_method_handler is not None
            assert rpc_method_handler.unary_unary is not None
            try:
                return rpc_method_handler.unary_unary(request, context)
            except (OperationalError, socket.timeout, queue.Empty, requests.exceptions.ConnectionError) as e:
                LOGGER.warning("Transient error caused RPC to abort. Try again.", exc_info=True)
                context.abort(grpc.StatusCode.ABORTED, "Try again - Transient error.")
                raise e
            except Exception as e:
                LOGGER.error("Uncaught server exception", exc_info=True)
                raise e

        intercepted_method_handler = grpc.unary_unary_rpc_method_handler(
            behavior,
            request_deserializer=rpc_method_handler.request_deserializer,
            response_serializer=rpc_method_handler.response_serializer,
        )
        return intercepted_method_handler
