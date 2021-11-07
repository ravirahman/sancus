import base64
from datetime import datetime
from typing import (
    Callable,
    Generator,
    Iterable,
    Protocol,
    Sequence,
    Type,
    TypeVar,
    cast,
)

import grpc
from common.constants import PAGINATION_LIMIT
from common.utils.datetime import (
    datetime_to_protobuf,
    get_current_datetime,
    protobuf_to_datetime,
)
from google.protobuf.any_pb2 import Any
from google.protobuf.message import Message
from protobufs.list_pb2 import NextToken

TRequest = TypeVar("TRequest", bound=Message)
TResponse = TypeVar("TResponse", bound=Message)
TResponseCo = TypeVar("TResponseCo", bound=Message, covariant=True)
TRequestCon = TypeVar("TRequestCon", bound=Message, contravariant=True)


class ListRequest(Protocol):
    def __init__(self, *, request: Message = Message(), nextToken: str = "") -> None:  # pylint: disable=invalid-name
        super().__init__()
        raise NotImplementedError()

    @property
    def nextToken(self) -> str:  # pylint: disable=invalid-name
        raise NotImplementedError()

    @property
    def request(self) -> Message:
        raise NotImplementedError()


TListRequest = TypeVar("TListRequest", bound=ListRequest)
TListRequestCon = TypeVar("TListRequestCon", bound=ListRequest, contravariant=True)


class ListResponse(Protocol):
    def __init__(self, *, response: Iterable[Message] = tuple(), nextToken: str = ""):  # pylint: disable=invalid-name
        super().__init__()
        raise NotImplementedError()

    @property
    def nextToken(self) -> str:  # pylint: disable=invalid-name
        raise NotImplementedError()

    @property
    def response(self) -> Iterable[Message]:
        raise NotImplementedError()


TListResponse = TypeVar("TListResponse", bound=ListResponse)


def list_rpc_yield(
    list_request: TListRequest, handler: Callable[[TListRequest], TListResponse]
) -> Generator[Message, None, None]:
    response = handler(list_request)
    while True:
        for output in response.response:
            yield output
        if response.nextToken == "":
            return
        response = handler(type(list_request)(nextToken=response.nextToken))


class ListRPC(Protocol[TListRequestCon, TListResponse, TRequestCon, TResponseCo]):
    list_response_type: Type[TListResponse]

    def __call__(self, request: TListRequestCon, context: grpc.ServicerContext) -> TListResponse:
        if request.nextToken != "":
            assert request.nextToken is not None
            next_token = NextToken()
            next_token.ParseFromString(base64.b64decode(request.nextToken.encode("utf8")))
            offset = next_token.offset
            req = type(request)()
            if not next_token.request.Unpack(req):
                raise ValueError("Invalid request inside next token.")
            req_cast = cast(TRequestCon, req)
            initial_request_timestamp = protobuf_to_datetime(next_token.initialRequestTimestamp)
            records = self.handle_subsequent_request(initial_request_timestamp, req_cast, offset, context)
            if len(records) > 0:
                next_token = NextToken(
                    offset=next_token.offset + PAGINATION_LIMIT,
                    request=next_token.request,
                    initialRequestTimestamp=next_token.initialRequestTimestamp,
                )
                serialized_next_token = base64.b64encode(next_token.SerializeToString()).decode("utf8")
            else:
                serialized_next_token = ""
            return self.list_response_type(response=records, nextToken=serialized_next_token)
        # it is possible that the request is blank, that is allowed
        req_cast = cast(TRequestCon, request.request)
        initial_request_timestamp = get_current_datetime()
        records = self.handle_initial_request(initial_request_timestamp, req_cast, context)
        if len(records) > 0:
            any_pb = Any()
            any_pb.Pack(request.request)
            next_token = NextToken(
                offset=PAGINATION_LIMIT,
                request=any_pb,
                initialRequestTimestamp=datetime_to_protobuf(initial_request_timestamp),
            )
            serialized_next_token = base64.b64encode(next_token.SerializeToString()).decode("utf8")
        else:
            serialized_next_token = ""
        return self.list_response_type(response=records, nextToken=serialized_next_token)

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: TRequestCon,
        context: grpc.ServicerContext,
    ) -> Sequence[TResponseCo]:
        raise NotImplementedError()

    def handle_subsequent_request(
        self,
        initial_request_timestamp: datetime,
        request: TRequestCon,
        offset: int,
        context: grpc.ServicerContext,
    ) -> Sequence[TResponseCo]:
        raise NotImplementedError()
