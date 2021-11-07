from bitcoin.core.key import CPubKey
from bitcoin.wallet import P2PKHBitcoinAddress
from common.constants import SECP256K1_GROUP, Blockchain
from common.sql.ecpt import EcPt
from common.sql.nizk import NIZK
from common.sql.uuid import UUID
from eth_keys import KeyAPI
from sqlalchemy import Column, Integer

from auditor.sql.base import Base


class Key(Base):
    __tablename__ = "Key"

    key_uuid = Column(UUID, primary_key=True)
    secp256k1_public_key = Column(EcPt(SECP256K1_GROUP), nullable=False, unique=True, index=True)

    permuted_secp256k1_public_key = Column(EcPt(SECP256K1_GROUP), nullable=False)
    permutation_nizk = Column(NIZK, nullable=False)  # nizk that shows correct key permutation

    ownership_commitment = Column(EcPt(SECP256K1_GROUP), nullable=False)
    ownernship_nzik = Column(NIZK, nullable=False)

    audit_publish_version = Column(Integer, nullable=False)

    def get_address(self, blockchain: Blockchain) -> str:
        public_key_ecpt = self.secp256k1_public_key
        if blockchain == Blockchain.ETH:
            eth_public_key = KeyAPI.PublicKey.from_compressed_bytes(public_key_ecpt.export())
            ethereum_address = eth_public_key.to_checksum_address()
            assert isinstance(ethereum_address, str)
            return ethereum_address
        if blockchain == Blockchain.BTC:
            bitcoin_public_key = CPubKey(public_key_ecpt.export())
            bitcoin_address = str(P2PKHBitcoinAddress.from_pubkey(bitcoin_public_key))
            return bitcoin_address
        raise ValueError(f"Unknown blockchain {blockchain}")

    # @hybrid_property
    # def p2wpkh_bitcoin_address(self) -> str:
    #     witver = 0
    #     public_key_ecpt = self.secp256k1_public_key
    #     bitcoin_public_key = CPubKey(public_key_ecpt.export())
    #     p2pkh_address = P2PKHBitcoinAddress.from_pubkey(bitcoin_public_key)
    #     bitcoin_address = str(P2WPKHBitcoinAddress.from_bytes(witver, p2pkh_address))
    #     return bitcoin_address
