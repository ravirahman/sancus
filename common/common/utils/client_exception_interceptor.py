import logging
import time
from abc import ABC
from typing import TYPE_CHECKING, Generic, TypeVar

import grpc
from google.protobuf.message import Message

TRequest = TypeVar("TRequest", bound=Message)
TResponse = TypeVar("TResponse", bound=Message)

if TYPE_CHECKING:
    from typing import Callable, Optional  # pylint: disable=ungrouped-imports

    class ClientInterceptor(
        grpc.UnaryUnaryClientInterceptor[TRequest, TResponse]
    ):  # pylint: disable=unsubscriptable-object
        pass


else:

    class ClientInterceptor(Generic[TRequest, TResponse], grpc.UnaryUnaryClientInterceptor, ABC):
        pass


LOGGER = logging.getLogger(__name__)


class ClientExceptionInterceptor(ClientInterceptor[TRequest, TResponse]):
    @staticmethod
    def intercept_unary_unary(
        continuation: "Callable[[grpc.ClientCallDetails, TRequest], grpc.CallFuture[TResponse]]",
        client_call_details: grpc.ClientCallDetails,
        request: TRequest,
    ) -> "grpc.CallFuture[TResponse]":
        while True:
            response = continuation(client_call_details, request)
            while not response.done():
                time.sleep(0.01)
            if response.code() == grpc.StatusCode.ABORTED:
                LOGGER.warning("Received an aborted rpc response with details(%s); trying again", response.details())
                continue  # try again
            return response
