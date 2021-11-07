from typing import Callable, Generator, Iterable, Protocol, TypeVar

from google.protobuf.message import Message


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
