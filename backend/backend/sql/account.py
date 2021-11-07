from decimal import Decimal

from common.constants import Currency
from common.sql.datetime import DateTime
from common.sql.enum import Enum
from common.sql.fixed_point import FixedPoint
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class Account(Base):
    __tablename__ = "account"
    uuid = Column(UUID, primary_key=True, default=generate_uuid4)
    account_type = Column(Integer, nullable=False)  # protobuf account type
    user_uuid = Column(UUID, nullable=False, index=True)
    currency = Column(Enum(Currency), nullable=False)
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
    available_amount = Column(FixedPoint, default=Decimal(0), nullable=False)
    pending_amount = Column(FixedPoint, default=Decimal(0), nullable=False)
    audit_version = Column(Integer)
    add_to_audit_timestamp = Column(DateTime)
