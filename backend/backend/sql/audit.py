from common.constants import Blockchain, Currency
from common.sql.bn import Bn
from common.sql.enum import Enum
from common.sql.protobuf import Protobuf
from protobufs.audit_pb2 import ExchangeRates, SolvencyProof
from sqlalchemy import Boolean, Column, DateTime, Integer

from backend.sql.base import Base


class Audit(Base):
    __tablename__ = "Audit"
    version_number = Column(Integer, primary_key=True, autoincrement=True)
    bitcoin_block = Column(Integer, nullable=False)
    ethereum_block = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    base_currency = Column(Enum(Currency), nullable=False)
    exchange_rates = Column(Protobuf(ExchangeRates), nullable=False)
    finalized = Column(Boolean, default=False, nullable=False)
    cumulative_asset_amount = Column(Bn)
    cumulative_asset_random = Column(Bn)
    cumulative_liability_amount = Column(Bn)
    cumulative_liability_random = Column(Bn)
    solvency_proof = Column(Protobuf(SolvencyProof))

    def get_block(self, blockchain: Blockchain) -> int:
        if blockchain == Blockchain.ETH:
            return self.ethereum_block
        if blockchain == Blockchain.BTC:
            return self.bitcoin_block
        raise ValueError("Invalid blockchain")
