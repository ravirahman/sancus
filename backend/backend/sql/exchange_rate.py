from common.sql.datetime import DateTime
from common.sql.fixed_point import FixedPoint
from sqlalchemy import Column, String

from backend.sql.base import Base


class ExchangeRate(Base):
    __tablename__ = "ExchangeRate"
    symbol = Column(String(10), primary_key=True)
    last_price = Column(FixedPoint, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
