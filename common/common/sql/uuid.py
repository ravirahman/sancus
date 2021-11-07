import uuid
from typing import TYPE_CHECKING, Optional

import sqlalchemy.types as types
from hexbytes.main import HexBytes
from sqlalchemy.engine.interfaces import Dialect

from common.sql.hex_string import HexString
from common.utils.uuid import bytes_to_uuid

if TYPE_CHECKING:
    UUIDEngine = types.TypeDecorator[uuid.UUID]  # pylint: disable=unsubscriptable-object
else:
    UUIDEngine = types.TypeDecorator


class UUID(UUIDEngine):
    impl = HexString(16)

    def process_bind_param(  # type: ignore[override]  # pylint: disable=no-self-use
        self, value: Optional[uuid.UUID], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[HexBytes]:
        if value is None:
            return None
        return HexBytes(value.bytes)

    def process_literal_param(self, value: Optional[uuid.UUID], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[bytes], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[uuid.UUID]:
        if value is None:
            return None
        return bytes_to_uuid(value)
