from common.sql.fixed_point import FixedPoint
from common.sql.hex_string import HexString
from sqlalchemy import Column, Integer, String

from auditor.sql.base import Base


class BTCVout(Base):
    __tablename__ = "BTCVout"

    txid = Column(HexString(32), primary_key=True)
    voutindex = Column(Integer, primary_key=True)
    address = Column(String(64), nullable=False)
    amount = Column(FixedPoint, nullable=False)
    block_number = Column(Integer, nullable=False)
    spent_block_number = Column(Integer)
