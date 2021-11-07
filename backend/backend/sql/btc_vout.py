from common.sql.datetime import DateTime
from common.sql.fixed_point import FixedPoint
from common.sql.hex_string import HexString
from common.utils.datetime import get_current_datetime
from sqlalchemy import Boolean, Column, Integer, String

from backend.sql.base import Base


class BTCVout(Base):
    __tablename__ = "BTCVout"

    txid = Column(HexString(32), primary_key=True)
    voutindex = Column(Integer, primary_key=True)
    address = Column(String(64), nullable=False, index=True)
    amount = Column(FixedPoint, nullable=False)
    block_number = Column(Integer, nullable=False)
    spent = Column(Boolean, nullable=False, default=False)
    spent_block_number = Column(Integer)
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
