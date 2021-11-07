from common.constants import Blockchain
from common.sql.enum import Enum
from common.sql.uuid import UUID
from sqlalchemy import Column, String

from auditor.sql.base import Base


class BlockchainAddressKey(Base):
    __tablename__ = "BlockchainAddressKey"

    blockchain = Column(Enum(Blockchain), primary_key=True)
    address = Column(String(64), primary_key=True)
    key_uuid = Column(UUID, nullable=False)
