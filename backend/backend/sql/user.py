from common.sql.datetime import DateTime
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from sqlalchemy import Column, String

from backend.sql.base import Base


class User(Base):
    __tablename__ = "User"

    user_uuid = Column(UUID, primary_key=True, default=generate_uuid4)
    username = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
