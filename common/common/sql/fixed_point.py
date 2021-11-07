import decimal
from typing import TYPE_CHECKING, Optional

import sqlalchemy.types as types
from sqlalchemy.engine.interfaces import Dialect

if TYPE_CHECKING:
    FixedPointEngine = types.TypeDecorator[decimal.Decimal]  # pylint: disable=unsubscriptable-object
else:
    FixedPointEngine = types.TypeDecorator


class FixedPoint(FixedPointEngine):
    impl = types.String(80)  # log10(2**256) = 78 (rounded) plus 1 for the decimal and 1 for a negative sign

    def process_bind_param(  # pylint: disable=no-self-use
        self,
        value: Optional[decimal.Decimal],
        dialect: Dialect,  # pylint: disable=unused-argument
    ) -> Optional[str]:
        if value is None:
            return None
        value_normalized = value.normalize()
        return str(value_normalized)

    def process_literal_param(self, value: Optional[decimal.Decimal], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[str], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[decimal.Decimal]:
        if value is None:
            return None
        ret = decimal.Decimal(value)
        return ret
