from decimal import Decimal

from common.constants import Currency
from common.sql.enum import Enum
from common.sql.fixed_point import FixedPoint
from common.sql.uuid import UUID
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class KeyCurrencyBlock(Base):
    # Tracks the delta (and cumulative) deposits and withdrawals for a currency for a given block
    # If there is no transaction for a given key-currency in a given block, then the previous KeyCurrencyBlock
    # for this key-currency is valid
    __tablename__ = "KeyCurrencyBlock"
    key_uuid = Column(UUID, primary_key=True, nullable=False, index=True)
    currency = Column(Enum(Currency), primary_key=True, nullable=False)
    block_number = Column(Integer, primary_key=True, nullable=False)
    withdrawal_amount = Column(FixedPoint, default=Decimal(0), nullable=False)
    deposit_amount = Column(FixedPoint, default=Decimal(0), nullable=False)
    cumulative_tracked_withdrawal_amount = Column(FixedPoint, nullable=False)
    cumulative_tracked_deposit_amount = Column(FixedPoint, nullable=False)
