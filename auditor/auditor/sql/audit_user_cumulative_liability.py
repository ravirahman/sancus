from common.constants import SECP256K1_GROUP
from common.sql.ecpt import EcPt
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from sqlalchemy import Boolean, Column, Integer

from auditor.sql.base import Base


class AuditUserCumulativeLiability(Base):
    __tablename__ = "AuditUserCumulativeLiability"

    audit_version = Column(Integer, primary_key=True)
    user_uuid = Column(UUID, primary_key=True)
    cumulative_base_currency_commitment = Column(EcPt(SECP256K1_GROUP), nullable=False)
    is_negative = Column(Boolean, nullable=False)
    # nizk showing that x \in [0, 2^128) -- i.e. it is positive, and it would take 2^127 users to cause overflow
    nizk = Column(NIZK, nullable=False)
