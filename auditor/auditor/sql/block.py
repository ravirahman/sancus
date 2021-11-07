from common.constants import Blockchain
from common.sql.datetime import DateTime
from common.sql.enum import Enum
from common.sql.hex_string import HexString
from sqlalchemy import Boolean, Column, Integer

from auditor.sql.base import Base


class Block(Base):
    __tablename__ = "Block"
    blockchain = Column(Enum(Blockchain), primary_key=True, nullable=False)
    block_number = Column(Integer, primary_key=True, nullable=False)
    block_hash = Column(HexString(32), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    processed = Column(Boolean, default=False, nullable=False)
