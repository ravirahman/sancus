from common.constants import SECP256K1_GROUP
from common.sql.bn import Bn
from common.sql.datetime import DateTime
from common.sql.ecpt import EcPt
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class AuditKeyAccountLiability(Base):
    __tablename__ = "AuditKeyAccountLiability"

    audit_version = Column(Integer, primary_key=True)
    key_uuid = Column(UUID, primary_key=True)
    account_uuid = Column(UUID, primary_key=True)
    p = Column(EcPt(SECP256K1_GROUP), nullable=False)
    v = Column(Bn, nullable=False)  # random value from Provisions protocol 1
    nizk = Column(NIZK, nullable=False)  # nizk. Storing so we can produce the same bytes

    # Adding a timestamp for a stable list ordering
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
