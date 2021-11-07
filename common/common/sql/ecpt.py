from typing import TYPE_CHECKING, Optional

import petlib.ec
import sqlalchemy.types as types
from sqlalchemy.engine.interfaces import Dialect

from common.sql.hex_string import HexString

if TYPE_CHECKING:
    EcPtEngine = types.TypeDecorator[petlib.ec.EcPt]  # pylint: disable=unsubscriptable-object
else:
    EcPtEngine = types.TypeDecorator


class EcPt(EcPtEngine):
    impl = HexString(33)

    def __init__(self, group: petlib.ec.EcGroup) -> None:
        super().__init__()
        self.group = group

    def process_bind_param(  # type: ignore[override]  # pylint: disable=no-self-use
        self, value: Optional[petlib.ec.EcPt], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[bytes]:
        if value is None:
            return None
        ret: bytes = value.export()
        return ret

    def process_literal_param(self, value: Optional[petlib.ec.EcPt], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[bytes], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[petlib.ec.EcPt]:
        if value is None:
            return None
        return petlib.ec.EcPt.from_binary(value, self.group)
