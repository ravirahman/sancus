from typing import TYPE_CHECKING, Optional, Type, Union

import sqlalchemy.types as types
from hexbytes.main import HexBytes
from sqlalchemy.engine.interfaces import Dialect

if TYPE_CHECKING:
    HexStringEngine = types.TypeDecorator[HexBytes]  # pylint: disable=unsubscriptable-object
else:
    HexStringEngine = types.TypeDecorator


class HexString(HexStringEngine):
    impl: Union[types.String, Type[types.String]] = types.String

    def __init__(self, binary_length: int) -> None:
        super().__init__(binary_length * 2 + 2)  # adding 2 for the leading "0x"

    def process_bind_param(  # pylint: disable=no-self-use
        self, value: Optional[HexBytes], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[str]:
        if value is None:
            return None
        return HexBytes(value).hex()

    def process_literal_param(self, value: Optional[HexBytes], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[str], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[HexBytes]:
        if value is None:
            return None
        return HexBytes(value)
