import zksk
from petlib.bn import Bn
from petlib.ec import EcPt
from zksk.primitives.rangeproof import PowerTwoRangeStmt

from common.constants import SECP256K1_ALTERNATIVE_GENERATOR, SECP256K1_GENERATOR
from common.utils.zk.exceptions import ProofFailedException


def generate_lte_commitment(lhs_amount: Bn, lhs_random: Bn, rhs_amount: Bn, rhs_random: Bn) -> zksk.base.NIZK:
    # generate a commitment to show that lhs_amount <= rhs_amount
    net_amount = rhs_amount - lhs_amount
    net_random = rhs_random - lhs_random
    net_amount_secret = zksk.Secret(net_amount, "net_amount")
    net_random_secret = zksk.Secret(net_random, "net_random")
    net_commitment = net_amount * SECP256K1_GENERATOR + net_random * SECP256K1_ALTERNATIVE_GENERATOR

    stmt = PowerTwoRangeStmt(
        net_commitment,
        SECP256K1_GENERATOR,
        SECP256K1_ALTERNATIVE_GENERATOR,
        num_bits=255,
        x=net_amount_secret,
        randomizer=net_random_secret,
    )
    nizk = stmt.prove()
    if __debug__:
        assert stmt.verify(nizk)
        rhs_commitment = rhs_amount * SECP256K1_GENERATOR + rhs_random * SECP256K1_ALTERNATIVE_GENERATOR
        lhs_commitment = lhs_amount * SECP256K1_GENERATOR + lhs_random * SECP256K1_ALTERNATIVE_GENERATOR
        verify_lte_commitment(lhs_commitment, rhs_commitment, nizk)
    return nizk


def verify_lte_commitment(lhs_commitment: EcPt, rhs_commitment: EcPt, nizk: zksk.base.NIZK) -> None:
    # WARNING: does not validate that rhs_commitment < 2^255. This should be gauranteed by an invariant
    # (e.g. RHS amount comes from on-chain deposits) or the auditor should require a separate range proof
    # for ths RHS amount < 2*255
    net_commitment = rhs_commitment - lhs_commitment
    net_amount_secret = zksk.Secret(name="net_amount")
    net_random_secret = zksk.Secret(name="net_random")
    stmt = PowerTwoRangeStmt(
        net_commitment,
        SECP256K1_GENERATOR,
        SECP256K1_ALTERNATIVE_GENERATOR,
        num_bits=255,
        x=net_amount_secret,
        randomizer=net_random_secret,
    )

    if not stmt.verify(nizk):
        raise ProofFailedException()
