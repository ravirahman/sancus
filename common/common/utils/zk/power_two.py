import zksk
from petlib.bn import Bn
from petlib.ec import EcPt
from zksk.primitives.rangeproof import PowerTwoRangeStmt

from common.constants import SECP256K1_ALTERNATIVE_GENERATOR, SECP256K1_GENERATOR
from common.utils.zk.exceptions import ProofFailedException


def generate_power_two_commitment(amount: Bn, random: Bn, num_bits: int) -> zksk.base.NIZK:
    amount_secret = zksk.Secret(amount, "amount")
    random_secret = zksk.Secret(random, "random")
    commitment = amount * SECP256K1_GENERATOR + random * SECP256K1_ALTERNATIVE_GENERATOR
    stmt = PowerTwoRangeStmt(
        commitment,
        SECP256K1_GENERATOR,
        SECP256K1_ALTERNATIVE_GENERATOR,
        num_bits=num_bits,
        x=amount_secret,
        randomizer=random_secret,
    )
    nizk = stmt.prove()
    if __debug__:
        assert stmt.verify(nizk)
        verify_power_two_commitment(commitment, num_bits, nizk)
    return nizk


def verify_power_two_commitment(commitment: EcPt, num_bits: int, nizk: zksk.base.NIZK) -> None:
    # WARNING: does not validate that rhs_commitment < 2^255. This should be gauranteed by an invariant
    # (e.g. RHS amount comes from on-chain deposits) or the auditor should require a separate range proof
    # for ths RHS amount < 2*255
    amount_secret = zksk.Secret(name="amount")
    random_secret = zksk.Secret(name="random")

    stmt = PowerTwoRangeStmt(
        commitment,
        SECP256K1_GENERATOR,
        SECP256K1_ALTERNATIVE_GENERATOR,
        num_bits=num_bits,
        x=amount_secret,
        randomizer=random_secret,
    )

    if not stmt.verify(nizk):
        raise ProofFailedException()
