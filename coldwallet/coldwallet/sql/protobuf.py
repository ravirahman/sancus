from typing import TYPE_CHECKING, Generic, Optional, Type, TypeVar, Union

import sqlalchemy.types as types
from google.protobuf.message import Message
from sqlalchemy.engine.interfaces import Dialect

TMessage = TypeVar("TMessage", bound=Message)


if TYPE_CHECKING:
    ProtobufEngine = types.TypeDecorator[TMessage]  # pylint: disable=unsubscriptable-object
else:
    ProtobufEngine = types.TypeDecorator


class Protobuf(ProtobufEngine, Generic[TMessage]):  # type: ignore[type-arg]
    impl: Union[Type[types.LargeBinary], types.LargeBinary] = types.LargeBinary

    def __init__(self, message_type: Type[TMessage], length: Optional[int] = None) -> None:
        self.message_type = message_type
        super().__init__(length)

    def process_bind_param(  # type: ignore[override]  # pylint: disable=no-self-use
        self, value: Optional[TMessage], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[bytes]:
        if value is None:
            return None
        return value.SerializeToString()

    def process_literal_param(self, value: Optional[TMessage], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(
        self, value: Optional[bytes], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[TMessage]:
        if value is None:
            return None
        message = self.message_type()
        message.ParseFromString(value)
        return message
