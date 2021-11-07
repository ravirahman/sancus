from typing import TYPE_CHECKING, Type, TypeVar

if TYPE_CHECKING:
    from sqlalchemy.sql.type_api import TypeEngine

    T = TypeVar("T")  # pylint: disable=invalid-name

    class Enum(TypeEngine[T]):  # pylint: disable=unsubscriptable-object
        def __init__(self, enum: Type[T]) -> None:  # pylint: disable=unused-argument
            ...


else:
    from sqlalchemy import Enum
