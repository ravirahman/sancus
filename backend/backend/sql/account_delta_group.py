from common.sql.datetime import DateTime
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class AccountDeltaGroup(Base):
    __tablename__ = "AccountDeltaGroup"

    uuid = Column(UUID, primary_key=True, default=generate_uuid4)
    user_uuid = Column(UUID, nullable=False, index=True)
    # pointer to the field in the challenge table
    # the challenge incorporates the exchange request uuid, along with the nizks for each currency.
    # it should be cryptographically constructed
    challenge_uuid = Column(UUID, nullable=False)
    status = Column(Integer, nullable=False)  # TransactionStatus enum

    # An AccountDeltas should be published in the audit only when the status is COMPLETED
    audit_publish_version = Column(Integer)
    add_to_audit_timestamp = Column(DateTime)

    # Adding a timestamp for a stable list ordering
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
