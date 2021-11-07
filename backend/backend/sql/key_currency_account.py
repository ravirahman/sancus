from typing import Optional

from common.constants import Currency
from common.sql.datetime import DateTime
from common.sql.enum import Enum
from common.sql.fixed_point import FixedPoint
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from sqlalchemy import Column, Float, Integer, func
from sqlalchemy.ext.hybrid import hybrid_property

from backend.sql.base import Base


class KeyCurrencyAccount(Base):
    __tablename__ = "KeyCurrencyAccount"
    key_uuid = Column(UUID, primary_key=True, nullable=False, index=True)
    currency = Column(Enum(Currency), primary_key=True, nullable=False)
    # If account_uuid is uuid.UUID(int=0), then it's either a hot or cold address (for this currency)
    # since the admin uuid is uuid.UUID(int=0)
    # If it's NULL, then it's an anonymous account
    # Otherwise, it's assigned to a specific account
    account_uuid = Column(UUID, index=True)

    # block when tracking begins. Set by process_block(). Defaults to NULL (not being tracked)
    initial_balance_block_number = Column(Integer)

    # balance for this key_currency_account at block initial_balance_block_number
    # It is defined to be the previous block so the balance at block X is the balance
    # this value + key_currency_block[block X].cumulative_deposits
    # - key_currency_block[block x].cumulative_withdrawals
    initial_balance = Column(FixedPoint)

    # this is an estimate of the available balance. Interally it is serialized as a string
    # so it can't be used for comparisions
    # deposits and canceled pending withdrawals increment it
    # creating pending withdrawals decrement it
    # it will always be <= the current available balance
    # initially None until it is processed
    # this field is only set when the account is not None
    available_balance = Column(FixedPoint)

    # this is an approximation of the current balance (as a float).
    # It can be used for comparisions as a heuristic
    # But it should NEVER be used for any financial calculations
    @hybrid_property
    def approximate_available_balance(self) -> Optional[float]:
        return None if self.available_balance is None else float(self.available_balance)

    @approximate_available_balance.expression  # type: ignore[no-redef]
    def approximate_available_balance(self):
        return func.cast(self.available_balance, Float)

    # When the key is owned by admin, and we create an internal transfer to this key currency, we increment
    # this field atomically
    # it is ONLY safe to change the ownership from admin to a user when this counter is 0
    pending_admin_deposits = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
