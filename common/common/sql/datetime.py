from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional, Type, Union

import pytz
import sqlalchemy.types as types
from sqlalchemy.engine.interfaces import Dialect

# stored as ints in microseconds

if TYPE_CHECKING:
    DateTimeEngine = types.TypeDecorator[datetime]  # pylint: disable=unsubscriptable-object
else:
    DateTimeEngine = types.TypeDecorator


class DateTime(DateTimeEngine):
    impl: Union[Type[types.BigInteger], types.BigInteger] = types.BigInteger

    def process_bind_param(  # type: ignore[override]  # pylint: disable=no-self-use
        self, value: Optional[datetime], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[int]:
        if value is None:
            return None
        assert value.tzinfo == pytz.UTC, f"timezone is {value.tzinfo}"
        seconds = int(value.timestamp())
        microseconds = value.microsecond
        return seconds * 1_000_000 + microseconds

    def process_literal_param(self, value: Optional[datetime], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[int], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[datetime]:
        if value is None:
            return None
        microseconds = value % 1_000_000
        seconds = value / 1_000_000
        return datetime.fromtimestamp(seconds, tz=pytz.UTC) + timedelta(microseconds=microseconds)
