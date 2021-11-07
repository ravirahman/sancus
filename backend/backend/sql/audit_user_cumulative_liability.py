import petlib.bn
from common.sql.bn import Bn
from common.sql.datetime import DateTime
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class AuditUserCumulativeLiability(Base):
    __tablename__ = "AuditUserCumulativeLiability"

    audit_version = Column(Integer, primary_key=True)
    user_uuid = Column(UUID, primary_key=True)

    # the total balance of the user in the base currency for this audit
    cumulative_to_currency_amount = Column(Bn, nullable=False, default=petlib.bn.Bn(0))

    # random value for the commitment
    cumulative_to_currency_v = Column(Bn, nullable=False, default=petlib.bn.Bn(0))

    # nizk showing that x \in [0, 2^128) -- i.e. it is positive, and it would take 2^127 users to cause overflow
    nizk = Column(NIZK, nullable=False)

    # Adding a timestamp for a stable list ordering
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
