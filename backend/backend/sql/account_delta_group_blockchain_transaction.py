from common.constants import Blockchain
from common.sql.enum import Enum
from common.sql.hex_string import HexString
from common.sql.uuid import UUID
from sqlalchemy import Column

from backend.sql.base import Base


class AccountDeltaGroupBlockchainTransaction(Base):
    __tablename__ = "AccountDeltaGroupBlockchainTransaction"

    account_delta_group_uuid = Column(UUID, primary_key=True, index=True)
    blockchain = Column(Enum(Blockchain), primary_key=True)

    # The blockchain withdrawal uuid returned by the blockchain client
    blockchain_withdrawal_uuid = Column(UUID, primary_key=True, index=True)
    # The identifier, combined with the Blockchain, which identify this transaction in the BlockchainTransaction table
    # Initially null until we queue it
    blockchain_transaction_identifier = Column(HexString(32))
