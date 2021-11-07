from typing import TYPE_CHECKING, Optional, Type, Union

import petlib.ec
import sqlalchemy.types as types
from sqlalchemy.engine.interfaces import Dialect

if TYPE_CHECKING:
    EcPtEngine = types.TypeDecorator[petlib.ec.EcPt]  # pylint: disable=unsubscriptable-object
else:
    EcPtEngine = types.TypeDecorator


class EcPt(EcPtEngine):
    impl: Union[types.LargeBinary, Type[types.LargeBinary]] = types.LargeBinary

    def __init__(self, group: petlib.ec.EcGroup, length: Optional[int] = None) -> None:
        self.group = group
        super().__init__(length)

    def process_bind_param(  # type: ignore[override]  # pylint: disable=no-self-use
        self, value: Optional[petlib.ec.EcPt], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[bytes]:
        if value is None:
            return None
        ret = value.export()
        assert isinstance(ret, bytes)
        return ret

    def process_literal_param(self, value: Optional[petlib.ec.EcPt], dialect: Dialect) -> Optional[str]:
        raise NotImplementedError()

    def process_result_value(  # pylint: disable=no-self-use
        self, value: Optional[bytes], dialect: Dialect  # pylint: disable=unused-argument
    ) -> Optional[petlib.ec.EcPt]:
        if value is None:
            return None
        ret = petlib.ec.EcPt.from_binary(value, self.group)
        assert isinstance(ret, petlib.ec.EcPt)
        return ret
