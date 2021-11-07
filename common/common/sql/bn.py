from typing import TYPE_CHECKING, Optional

import petlib.bn
import sqlalchemy.types as types
from sqlalchemy.engine.interfaces import Dialect

if TYPE_CHECKING:
    BnEngine = types.TypeDecorator[petlib.bn.Bn]  # pylint: disable=unsubscriptable-object
else:
    BnEngine = types.TypeDecorator


class Bn(BnEngine):
    impl = types.String(79)  # log10(2**256) = 78 rounded up plus 1 for a negative sign

    def process_bind_param(  # pylint: disable=no-self-use
        self, value: Optional[petlib.bn.Bn], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[str]:
        if value is None:
            return None
        return str(value)

    def process_literal_param(self, value: Optional[petlib.bn.Bn], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[str], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[petlib.bn.Bn]:
        if value is None:
            return None
        return petlib.bn.Bn.from_decimal(value)
