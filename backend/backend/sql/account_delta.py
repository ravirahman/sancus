from common.sql.bn import Bn
from common.sql.uuid import UUID
from sqlalchemy import Column

from backend.sql.base import Base


class AccountDelta(Base):
    __tablename__ = "AccountDelta"

    account_delta_group_uuid = Column(UUID, primary_key=True, nullable=False, index=True)
    account_uuid = Column(UUID, primary_key=True, nullable=False, index=True)
    amount = Column(Bn, nullable=False)
    random_val = Column(Bn, nullable=False)
