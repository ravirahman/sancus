from common.constants import Blockchain
from common.sql.datetime import DateTime
from common.sql.enum import Enum
from common.sql.hex_string import HexString
from sqlalchemy import Boolean, Column, Index, Integer

from backend.sql.base import Base


class Block(Base):
    __tablename__ = "Block"
    blockchain = Column(Enum(Blockchain), primary_key=True, nullable=False)
    block_number = Column(Integer, primary_key=True, nullable=False)
    block_hash = Column(HexString(32), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    processed = Column(Boolean, nullable=False, default=False)


Index("blockchain_block_hash", Block.blockchain, Block.block_hash)
