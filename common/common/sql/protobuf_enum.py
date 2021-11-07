from typing import TYPE_CHECKING, Generic, Optional, Type, TypeVar, Union, cast

import sqlalchemy.types as types
from sqlalchemy.engine.interfaces import Dialect

TEnumType = TypeVar("TEnumType", bound=int)

if TYPE_CHECKING:
    ProtobufEnumEngine = types.TypeDecorator[TEnumType]  # pylint: disable=unsubscriptable-object
else:
    ProtobufEnumEngine = types.TypeDecorator


class ProtobufEnum(Generic[TEnumType], ProtobufEnumEngine):  # type: ignore[type-arg]
    impl: Union[Type[types.Integer], types.Integer] = types.Integer

    # def __init__(self, enum_type: Type[TEnumType]) -> None:
    #     self.enum_type = enum_type
    #     super().__init__()

    def process_bind_param(  # type: ignore[override]  # pylint: disable=no-self-use
        self, value: Optional[TEnumType], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[int]:
        if value is None:
            return None
        return value

    def process_literal_param(self, value: Optional[TEnumType], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[int], dialect: Dialect  # pylint: disable=unused-argument,no-self-use
    ) -> Optional[TEnumType]:
        if value is None:
            return None
        return cast(TEnumType, value)
