import petlib.bn
from common.constants import SECP256K1_ORDER, Currency
from common.sql.bn import Bn
from common.sql.datetime import DateTime
from common.sql.enum import Enum
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class AuditUserCurrencyLiability(Base):
    __tablename__ = "AuditUserCurrencyLiability"

    audit_version = Column(Integer, primary_key=True)
    user_uuid = Column(UUID, primary_key=True)
    currency = Column(Enum(Currency), primary_key=True)

    cumulative_deposit_amount = Column(Bn, nullable=False, default=petlib.bn.Bn(0))
    cumulative_deposit_v = Column(Bn, nullable=False, default=petlib.bn.Bn(0))

    cumulative_account_delta_amount = Column(Bn, nullable=False)  # should be set to the previous audit for the user
    cumulative_account_delta_v = Column(Bn, nullable=False)  # should be set to the previous audit for the user

    to_currency_v = Column(Bn, nullable=False, default=SECP256K1_ORDER.random)
    to_currency_amount = Column(Bn)  # set by user_cumulative_liability
    to_currency_nizk = Column(NIZK)  # set by user_cumulative_liability

    # Adding a timestamp for a stable list ordering
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
