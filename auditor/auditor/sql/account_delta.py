from common.constants import SECP256K1_GROUP
from common.sql.ecpt import EcPt
from common.sql.uuid import UUID
from sqlalchemy import Column

from auditor.sql.base import Base


class AccountDelta(Base):
    __tablename__ = "AccountDelta"

    account_delta_group_uuid = Column(UUID, primary_key=True)
    account_uuid = Column(UUID, primary_key=True)
    commitment = Column(EcPt(SECP256K1_GROUP), nullable=False)
