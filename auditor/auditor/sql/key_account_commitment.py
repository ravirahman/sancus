from common.constants import SECP256K1_GROUP
from common.sql.ecpt import EcPt
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from sqlalchemy import Column, Integer

from auditor.sql.base import Base


class KeyAccountCommitment(Base):
    __tablename__ = "KeyAccountCommitment"

    key_uuid = Column(UUID, primary_key=True)
    account_uuid = Column(UUID, primary_key=True)

    # Block at after which this commitment is valid
    block_number = Column(Integer, nullable=False)

    commitment = Column(EcPt(SECP256K1_GROUP), nullable=False)
    nizk = Column(NIZK, nullable=False)  # nizk for ownership commitment
    audit_publish_version = Column(Integer, nullable=False)
