from common.sql.uuid import UUID
from sqlalchemy import Column, Integer, LargeBinary

from auditor.sql.base import Base


class UserKey(Base):
    __tablename__ = "UserKey"
    user_key_uuid = Column(UUID, primary_key=True)
    credential_id = Column(LargeBinary, nullable=False)
    user_uuid = Column(  # defining as unique as currently users are allowed only one key.
        UUID, nullable=False, unique=True
    )
    public_key = Column(LargeBinary, nullable=False)
    credential_type = Column(Integer, nullable=False)
    audit_publish_version = Column(Integer, nullable=False)
