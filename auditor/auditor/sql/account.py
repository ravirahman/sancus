from common.constants import Currency
from common.sql.enum import Enum
from common.sql.uuid import UUID
from sqlalchemy import Column, Integer

from auditor.sql.base import Base


class Account(Base):
    __tablename__ = "account"
    uuid = Column(UUID, primary_key=True)
    account_type = Column(Integer, nullable=False)  # protobuf account type
    user_uuid = Column(UUID, nullable=False)
    currency = Column(Enum(Currency), nullable=False)
    audit_version = Column(Integer, nullable=False)
