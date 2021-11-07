from common.sql.uuid import UUID
from sqlalchemy import Column, Integer

from auditor.sql.base import Base


class AccountDeltaGroup(Base):
    __tablename__ = "AccountDeltaGroup"

    uuid = Column(UUID, primary_key=True)
    user_uuid = Column(UUID, nullable=False)
    # pointer to the field in the challenge table
    # the challenge incorporates the exchange request uuid, along with the nizks for each currency.
    # it should be cryptographically constructed
    challenge_uuid = Column(UUID, nullable=False)

    # An AccountDeltas should be published in the audit only when the status is COMPLETED
    audit_publish_version = Column(Integer, nullable=False)
