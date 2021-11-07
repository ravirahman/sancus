from typing import TYPE_CHECKING, Optional

import sqlalchemy.types as types
import zksk.base
from sqlalchemy.dialects.mysql import MEDIUMBLOB
from sqlalchemy.engine.interfaces import Dialect

if TYPE_CHECKING:
    NIZKEngine = types.TypeDecorator[zksk.base.NIZK]  # pylint: disable=unsubscriptable-object
else:
    NIZKEngine = types.TypeDecorator


class NIZK(NIZKEngine):
    impl: types.LargeBinary = types.LargeBinary().with_variant(MEDIUMBLOB, "mysql")  # type: ignore[arg-type,assignment]

    def process_bind_param(  # type: ignore[override]  # pylint: disable=no-self-use
        self, value: Optional[zksk.base.NIZK], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[bytes]:
        if value is None:
            return None
        assert isinstance(value, zksk.base.NIZK)
        ret = value.serialize()
        assert isinstance(ret, bytes)
        return ret

    def process_literal_param(self, value: Optional[zksk.base.NIZK], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[bytes], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[zksk.base.NIZK]:
        if value is None:
            return None
        assert isinstance(value, bytes)
        ret = zksk.base.NIZK.deserialize(value)
        assert isinstance(ret, zksk.base.NIZK)
        return ret
