from typing import Tuple

import petlib.bn
import petlib.ec
import zksk
import zksk.composition

from common.constants import SECP256K1_ALTERNATIVE_GENERATOR
from common.utils.zk.exceptions import ProofFailedException


def generate_bit_commitment(
    s: bool,
    r: petlib.bn.Bn,
    G: petlib.ec.EcPt,
) -> Tuple[petlib.ec.EcPt, zksk.base.NIZK]:
    # adapted from https://zksk.readthedocs.io/en/latest/index.html
    commitment = petlib.bn.Bn(s) * G + r * SECP256K1_ALTERNATIVE_GENERATOR
    r_s = zksk.Secret(r, "r")
    stmt = zksk.DLRep(commitment, r_s * SECP256K1_ALTERNATIVE_GENERATOR, simulated=s) | zksk.DLRep(
        commitment - G, r_s * SECP256K1_ALTERNATIVE_GENERATOR, simulated=(not s)
    )
    nizk = stmt.prove()
    assert stmt.verify(nizk), "proof failed"
    verify_bit_commitment(commitment, G, nizk)
    return commitment, nizk


def verify_bit_commitment(commitment: petlib.ec.EcPt, G: petlib.ec.EcPt, nizk: zksk.base.NIZK) -> None:
    r_s = zksk.Secret(name="r")
    stmt = zksk.DLRep(commitment, r_s * SECP256K1_ALTERNATIVE_GENERATOR) | zksk.DLRep(
        commitment - G, r_s * SECP256K1_ALTERNATIVE_GENERATOR
    )
    if not stmt.verify(nizk):
        raise ProofFailedException()
