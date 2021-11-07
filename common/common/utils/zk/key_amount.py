from typing import Tuple

import zksk
from petlib.bn import Bn
from petlib.ec import EcPt

from common.constants import SECP256K1_ALTERNATIVE_GENERATOR, SECP256K1_GENERATOR
from common.utils.zk.bit_commitment import verify_bit_commitment
from common.utils.zk.exceptions import ProofFailedException


def create_key_amount_commitment(
    *,
    amount: Bn,  # the amount of crypto to use for this commitment
    v: Bn,  # a random number, as defined in provisions protocol 1
    t: Bn,  # a random number, as defined in provisions protocol 1
    y: EcPt,  # the permuted public key
    x_hat: Bn = Bn(0),  # s * permuted private key. defaults to 0 (i.e. s = 0)
) -> Tuple[EcPt, EcPt, zksk.base.NIZK]:
    s = x_hat != Bn(0)

    b = amount * SECP256K1_GENERATOR
    p = s * b + v * SECP256K1_ALTERNATIVE_GENERATOR
    l = s * y + t * SECP256K1_ALTERNATIVE_GENERATOR

    # compute p_i = s_i * b_i + v_i * H
    s_secret = zksk.Secret(s, "s")
    v_secret = zksk.Secret(v, "v")
    x_hat_secret = zksk.Secret(x_hat, "x_hat")
    t_secret = zksk.Secret(t, "t")

    # balance commitment
    stmt_1 = zksk.DLRep(p, s_secret * b + v_secret * SECP256K1_ALTERNATIVE_GENERATOR)

    # ownership commitment
    stmt_2 = zksk.DLRep(l, s_secret * y + t_secret * SECP256K1_ALTERNATIVE_GENERATOR)

    # private key commitment
    stmt_3 = zksk.DLRep(l, x_hat_secret * SECP256K1_GENERATOR + t_secret * SECP256K1_ALTERNATIVE_GENERATOR)

    stmt_combined = stmt_1 & stmt_2 & stmt_3
    nizk = stmt_combined.prove()
    assert stmt_combined.verify(nizk), "proof failed"
    return p, l, nizk


def verify_key_amount_commitment(
    amount: Bn,  # the amount of crypto to use for this commitment
    y: EcPt,  # permuted public key
    p: EcPt,  # balance commitment
    l: EcPt,  # ownership / private key commitment
    key_amount_nizk: zksk.base.NIZK,
    bit_commitment_nizk: zksk.base.NIZK,
) -> None:
    s_secret = zksk.Secret(name="s")
    v_secret = zksk.Secret(name="v")
    x_hat_secret = zksk.Secret(name="x_hat")
    t_secret = zksk.Secret(name="t")

    b = amount * SECP256K1_GENERATOR

    # balance commitment
    stmt_1 = zksk.DLRep(p, s_secret * b + v_secret * SECP256K1_ALTERNATIVE_GENERATOR)

    # ownership commitment
    stmt_2 = zksk.DLRep(l, s_secret * y + t_secret * SECP256K1_ALTERNATIVE_GENERATOR)

    # private key commitment
    stmt_3 = zksk.DLRep(l, x_hat_secret * SECP256K1_GENERATOR + t_secret * SECP256K1_ALTERNATIVE_GENERATOR)

    stmt_combined = stmt_1 & stmt_2 & stmt_3
    if not stmt_combined.verify(key_amount_nizk):
        raise ProofFailedException()

    verify_bit_commitment(l, y, bit_commitment_nizk)
