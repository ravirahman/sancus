from common.constants import Currency
from common.sql.enum import Enum
from common.sql.protobuf import Protobuf
from protobufs.audit_pb2 import ExchangeRates
from sqlalchemy import Boolean, Column, DateTime, Integer

from auditor.sql.base import Base


class Audit(Base):
    __tablename__ = "Audit"
    version_number = Column(Integer, primary_key=True)
    bitcoin_block = Column(Integer, nullable=False)
    ethereum_block = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    base_currency = Column(Enum(Currency), nullable=False)
    exchange_rates = Column(Protobuf(ExchangeRates), nullable=False)
    finished = Column(Boolean, default=False)
