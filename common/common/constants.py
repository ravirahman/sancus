import uuid
from datetime import timedelta
from enum import Enum
from typing import Dict, Final

import petlib.bn
import petlib.ec

SECP256K1_CURVE_ID = 714
SECP256K1_GROUP = petlib.ec.EcGroup(nid=SECP256K1_CURVE_ID)
SECP256K1_GENERATOR = SECP256K1_GROUP.generator()
SECP256K1_ORDER = SECP256K1_GROUP.order()

PAGINATION_LIMIT = 25

# used in time.sleep() calls to release the GIL and spin the thread
# 50 ms seems reasonable
SPIN_SLEEP_SECONDS = 0.05

MAX_USER_BAL_BITS = 127
MAX_USER_BAL = petlib.bn.Bn(2) ** MAX_USER_BAL_BITS

SECP256K1_ALTERNATIVE_GENERATOR = petlib.ec.EcPt.from_binary(
    # TODO: prove that this is a nothing-up-my-sleeve number
    bytes.fromhex("03ec68bb4ad27f27987c1d4040a32e759a1aa538a6c1f32aa2d4d38a6f597d2b1e"),
    SECP256K1_GROUP,
)


class Currency(Enum):
    BTC = "Bitcoin"
    ETH = "Ethereum"
    GUSD = "Gemini USD"


class Blockchain(Enum):
    BTC = "Bitcoin"
    ETH = "Ethereum"


CURRENCY_TO_BLOCKCHAIN: Final[Dict[Currency, Blockchain]] = {
    Currency.BTC: Blockchain.BTC,
    Currency.ETH: Blockchain.ETH,
    Currency.GUSD: Blockchain.ETH,
}

CURRENCY_DECIMALS: Final[Dict[Currency, int]] = {
    Currency.BTC: 8,
    Currency.ETH: 18,
    Currency.GUSD: 2,
}

AUDIT_BASE_CURRENCY = Currency.GUSD

CURRENCY_PRECISIONS: Final[Dict[Currency, int]] = {k: 10 ** v for k, v in CURRENCY_DECIMALS.items()}

ADMIN_UUID = uuid.UUID(int=0)

BLOCKCHAIN_TIMESTAMP_EPSILON = timedelta(seconds=30)

# to generate a new random generator
"""
import petlib.ec
group = petlib.ec.EcGroup(714)
print((group.order().random() * group.generator()).export().hex())
"""
