import uuid
from typing import TYPE_CHECKING, Optional

import sqlalchemy.types as types
from sqlalchemy.engine.interfaces import Dialect

if TYPE_CHECKING:
    UUIDEngine = types.TypeDecorator[uuid.UUID]  # pylint: disable=unsubscriptable-object
else:
    UUIDEngine = types.TypeDecorator


class UUID(UUIDEngine):
    impl = types.Unicode(32)

    def process_bind_param(  # pylint: disable=no-self-use
        self, value: Optional[uuid.UUID], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[str]:
        if value is None:
            return None
        return value.hex

    def process_literal_param(self, value: Optional[uuid.UUID], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[str], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[uuid.UUID]:
        if value is None:
            return None
        return uuid.UUID(value)
