from common.constants import Blockchain
from common.sql.datetime import DateTime
from common.sql.enum import Enum
from common.sql.hex_string import HexString
from common.sql.protobuf import Protobuf
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from google.protobuf.any_pb2 import Any
from sqlalchemy import Boolean, Column, Index, Integer, LargeBinary

from backend.sql.base import Base


class BlockchainWithdrawal(Base):
    __tablename__ = "BlockchainWithdrawal"
    uuid = Column(UUID, primary_key=True, default=generate_uuid4)
    blockchain = Column(Enum(Blockchain), nullable=False)
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    tx_params = Column(Protobuf(Any), nullable=False)
    # Whether there may be any destination addresses from the withdrawal which go to
    # admin keys. If so, upon creating the withdrawal, we incrmented the pending admin
    # deposit counter. Here, we need to create a note whether we decremented the counter
    # once the transaction has been confirmed for at least num_confirmations
    # this flag should be flipped atomically when the counters are decremented
    pending_admin_deposits_reconciled = Column(Boolean, nullable=False, default=False)

    # defaults to Null. When set, then the background job will broadcast it onto the chain
    # and move it into the pending withdrawals
    # when this signed tx is set, then the transaction MUST be broadcasted. Do not replace
    # with a dummy
    signed_tx = Column(LargeBinary)

    txn_hash = Column(HexString(32))  # this field is set whenever the transaction is broadcast.
    last_broadcast_at = Column(DateTime)
    block_number = Column(Integer)


Index("blockchain_block_number", BlockchainWithdrawal.blockchain, BlockchainWithdrawal.block_number)
