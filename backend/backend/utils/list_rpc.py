import uuid
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
from common.utils.datetime import get_current_datetime
from google.protobuf.message import Message

from backend.utils.jwt_client import JWTClient, JWTException

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
    next_token_name: str

    @property
    def jwt_client(self) -> JWTClient:
        raise NotImplementedError()

    def __call__(self, request: TListRequestCon, context: grpc.ServicerContext, user_uuid: uuid.UUID) -> TListResponse:
        if request.nextToken != "":
            assert request.nextToken is not None
            try:
                initial_request_timestamp, offset, req = self.jwt_client.decode_next_token_jwt(
                    user_uuid,
                    self.next_token_name,
                    request.nextToken,
                    type(request.request),
                )
            except JWTException as e:
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "Invalid next token")
                raise ValueError("Invalid next token") from e
            req_cast = cast(TRequestCon, req)
            records = self.handle_subsequent_request(initial_request_timestamp, req_cast, offset, context, user_uuid)
            if len(records) > 0:
                serialized_next_token = self.jwt_client.issue_next_token_jwt(
                    initial_request_timestamp, user_uuid, self.next_token_name, req_cast, offset + PAGINATION_LIMIT
                )
            else:
                serialized_next_token = ""
            return self.list_response_type(response=records, nextToken=serialized_next_token)
        # it is possible that the request is blank, that is allowed
        request_timestamp = get_current_datetime()
        req_cast = cast(TRequestCon, request.request)
        records = self.handle_initial_request(request_timestamp, req_cast, context, user_uuid)
        if len(records) > 0:
            serialized_next_token = self.jwt_client.issue_next_token_jwt(
                request_timestamp, user_uuid, self.next_token_name, request.request, PAGINATION_LIMIT
            )
        else:
            serialized_next_token = ""
        ans = self.list_response_type(response=records, nextToken=serialized_next_token)
        return ans

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: TRequestCon,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[TResponseCo]:
        raise NotImplementedError()

    def handle_subsequent_request(
        self,
        initial_request_timestamp: datetime,
        request: TRequestCon,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[TResponseCo]:
        raise NotImplementedError()
