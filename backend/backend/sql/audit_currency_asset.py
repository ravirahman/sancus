import petlib.bn
from common.constants import SECP256K1_ORDER, Currency
from common.sql.bn import Bn
from common.sql.datetime import DateTime
from common.sql.enum import Enum
from common.sql.nizk import NIZK
from common.utils.datetime import get_current_datetime
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class AuditCurrencyAsset(Base):
    __tablename__ = "AuditCurrencyAsset"

    audit_version = Column(Integer, primary_key=True)
    currency = Column(Enum(Currency), primary_key=True)

    cumulative_assets = Column(Bn, nullable=False, default=petlib.bn.Bn(0))
    cumulative_v = Column(Bn, nullable=False, default=petlib.bn.Bn(0))  # random value from Provisions protocol 1

    to_currency_v = Column(Bn, nullable=False, default=SECP256K1_ORDER.random)
    to_currency_amount = Column(Bn)  # set by finalize_audit
    to_currency_nizk = Column(NIZK)  # set by finalize_audit

    # Adding a timestamp for a stable list ordering
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
