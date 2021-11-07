from common.sql.bn import Bn
from common.sql.datetime import DateTime
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from sqlalchemy import Boolean, Column, Integer

from backend.sql.base import Base


class KeyAccountCommitment(Base):
    __tablename__ = "KeyAccountCommitment"

    key_uuid = Column(UUID, primary_key=True, index=True)
    account_uuid = Column(UUID, primary_key=True, index=True)

    # Block at after which this commitment is valid
    # It is set by process_block
    # So any following block (in the audit) must obey this commitment
    block_number = Column(Integer)

    # bit indiciating whether this deposit account will get credit for deposits made to this key
    s = Column(Boolean, nullable=False)
    # random value for bit commitment that shows we will credit (or not credit) funds for this key
    r = Column(Bn, nullable=False)
    nizk = Column(NIZK, nullable=False)  # nizk for ownership commitment
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)

    audit_publish_version = Column(Integer)
    add_to_audit_timestamp = Column(DateTime)
