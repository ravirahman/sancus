from common.sql.datetime import DateTime
from common.sql.fixed_point import FixedPoint
from common.sql.protobuf import Protobuf
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from google.protobuf.any_pb2 import Any
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class Transaction(Base):
    __tablename__ = "Transaction"
    uuid = Column(UUID, primary_key=True, default=generate_uuid4, nullable=False)
    account_uuid = Column(UUID, nullable=False, index=True)
    transaction_type = Column(Integer, nullable=False)  # TransactionType protobuf enum
    timestamp = Column(DateTime, default=get_current_datetime, nullable=False)
    status = Column(Integer, nullable=False)  # TransactionStatus protobuf enum
    amount = Column(FixedPoint, nullable=False)
    extra = Column(Protobuf(Any))  # Of type ExchangeTransaction, WithdrawalTransaction, or None (for deposits)
