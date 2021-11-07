import petlib.bn
import petlib.ec
from bitcoin.core.key import CPubKey
from bitcoin.wallet import P2PKHBitcoinAddress
from eth_keys import KeyAPI
from sqlalchemy import Column, String
from sqlalchemy.engine.default import DefaultExecutionContext

from coldwallet.sql.base import Base
from coldwallet.sql.bn import Bn
from coldwallet.sql.ecpt import EcPt
from coldwallet.sql.uuid import UUID
from coldwallet.utils.uuid import generate_uuid4

SECP256K1_CURVE_ID = 714
SECP256K1_GROUP = petlib.ec.EcGroup(nid=SECP256K1_CURVE_ID)


def generate_public_key(context: DefaultExecutionContext) -> petlib.ec.EcPt:
    parameters = context.get_current_parameters()  # type: ignore[attr-defined]
    private_key = parameters["private_key"]
    public_key = private_key * SECP256K1_GROUP.generator()
    return public_key


def generate_ethereum_address(context: DefaultExecutionContext) -> str:
    parameters = context.get_current_parameters()  # type: ignore[attr-defined]
    public_key_ecpt = parameters["secp256k1_public_key"]
    eth_public_key = KeyAPI.PublicKey.from_compressed_bytes(
        public_key_ecpt.export(form=petlib.ec.POINT_CONVERSION_COMPRESSED)
    )
    ethereum_address = eth_public_key.to_checksum_address()
    assert isinstance(ethereum_address, str)
    return ethereum_address


def generate_bitcoin_address(context: DefaultExecutionContext) -> str:
    parameters = context.get_current_parameters()  # type: ignore[attr-defined]
    public_key_ecpt = parameters["secp256k1_public_key"]
    bitcoin_public_key = CPubKey(public_key_ecpt.export(form=petlib.ec.POINT_CONVERSION_COMPRESSED))
    bitcoin_address = str(P2PKHBitcoinAddress.from_pubkey(bitcoin_public_key))
    return bitcoin_address


class Key(Base):
    __tablename__ = "Key"

    key_uuid = Column(UUID, primary_key=True, autoincrement=False, default=generate_uuid4)
    private_key = Column(Bn(), unique=True)
    secp256k1_public_key = Column(EcPt(SECP256K1_GROUP), unique=True, default=generate_public_key)
    ethereum_address = Column(String(42), index=True, unique=True, default=generate_ethereum_address)
    bitcoin_address = Column(
        String(35), index=True, unique=True, default=generate_bitcoin_address
    )  # cached field, determined by the private key
