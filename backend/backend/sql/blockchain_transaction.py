from common.constants import Blockchain
from common.sql.enum import Enum
from common.sql.hex_string import HexString
from common.sql.uuid import UUID
from sqlalchemy import Column, Integer

from backend.sql.base import Base


class BlockchainTransaction(Base):
    __tablename__ = "BlockchainTransaction"
    blockchain = Column(Enum(Blockchain), primary_key=True, nullable=False)
    blockchain_transaction_identifier = Column(HexString(32), primary_key=True, nullable=False)
    block_number = Column(Integer, index=True)
    transaction_uuid = Column(UUID, nullable=False, index=True)
