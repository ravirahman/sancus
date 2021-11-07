import petlib.bn
import petlib.ec
from bitcoin.core.key import CPubKey
from bitcoin.wallet import P2PKHBitcoinAddress
from common.constants import (
    SECP256K1_GENERATOR,
    SECP256K1_GROUP,
    SECP256K1_ORDER,
    Blockchain,
)
from common.sql.bn import Bn
from common.sql.datetime import DateTime
from common.sql.ecpt import EcPt
from common.sql.nizk import NIZK
from common.sql.protobuf_enum import ProtobufEnum
from common.sql.uuid import UUID
from common.utils.datetime import get_current_datetime
from common.utils.uuid import generate_uuid4
from common.utils.zk.bit_commitment import generate_bit_commitment
from eth_keys import KeyAPI
from protobufs.key_pb2 import KeyType
from sqlalchemy import Column, Integer
from sqlalchemy.ext.hybrid import hybrid_property

from backend.sql.base import Base


def generate_public_key(private_key: petlib.bn.Bn) -> petlib.ec.EcPt:
    public_key = private_key * SECP256K1_GENERATOR
    return public_key


class Key(Base):
    __tablename__ = "Key"
    ownership_s: bool

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[call-arg]
        if self.secp256k1_public_key is None:
            self.secp256k1_public_key = generate_public_key(self.private_key)
        if self.permuted_secp256k1_public_key is None:
            self.permuted_secp256k1_public_key = generate_public_key(self.permuted_private_key)
        if self.ownership_r is None:
            self.ownership_r = SECP256K1_ORDER.random()
        if self.ownership_nizk is None:
            _, nizk = generate_bit_commitment(
                s=self.ownership_s, r=self.ownership_r, G=self.permuted_secp256k1_public_key
            )
            self.ownership_nizk = nizk

    key_uuid = Column(UUID, primary_key=True, default=generate_uuid4)
    key_type = Column(ProtobufEnum["KeyType.V"], nullable=False)  # from the protobuf.
    private_key = Column(Bn)  # null if key is cold or anonymous
    secp256k1_public_key = Column(EcPt(SECP256K1_GROUP), unique=True, index=True, nullable=False)

    @hybrid_property  # type: ignore[no-redef]
    def ownership_s(self) -> bool:  # pylint: disable=function-redefined
        return self.key_type in (KeyType.HOT, KeyType.COLD)

    @ownership_s.expression  # type: ignore[no-redef]
    def ownership_s(cls) -> bool:  # pylint: disable=function-redefined,no-self-argument
        return cls.key_type == KeyType.HOT or cls.key_type == KeyType.COLD

    ownership_r = Column(Bn, nullable=False)
    ownership_nizk = Column(NIZK, nullable=False)

    # if null, that means we don't actually own this key -- i.e. self.ownership_s is False
    permuted_private_key = Column(Bn)
    permuted_secp256k1_public_key = Column(EcPt(SECP256K1_GROUP), nullable=False)
    permutation_nizk = Column(NIZK, nullable=False)  # nizk that shows correct key permutation

    audit_publish_version = Column(Integer)
    add_to_audit_timestamp = Column(DateTime)

    # stores the last used transaction nonce. This field is incremented whenever a pending transaction is created.
    # It is NEVER decremented. Only applicable for hot and cold accounts.
    ethereum_transaction_count = Column(Integer, nullable=False, default=0)

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

    # Adding a timestamp for a stable list ordering
    created_at = Column(DateTime, default=get_current_datetime, nullable=False)
