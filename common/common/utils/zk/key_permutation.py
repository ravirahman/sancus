from typing import Tuple

import petlib
import zksk
from zksk.base import NIZK

from common.constants import SECP256K1_GENERATOR, SECP256K1_ORDER
from common.utils.zk.exceptions import ProofFailedException


def permute_public_key(public_key: petlib.ec.EcPt, k: petlib.bn.Bn) -> Tuple[petlib.ec.EcPt, NIZK]:
    permuted_public_key = k * public_key

    k_s = zksk.Secret(name="k_s", value=k)
    stmt = zksk.DLRep(k * public_key, k_s * public_key)
    nizk = stmt.prove()

    return permuted_public_key, nizk


def permute_private_key(private_key: petlib.bn.Bn, k: petlib.bn.Bn) -> Tuple[petlib.bn.Bn, NIZK]:
    public_key = private_key * SECP256K1_GENERATOR
    permuted_private_key = (k * private_key) % SECP256K1_ORDER
    permuted_public_key = permuted_private_key * SECP256K1_GENERATOR

    k_s = zksk.Secret(name="k_s", value=k)
    stmt = zksk.DLRep(permuted_public_key, k_s * public_key)
    nizk = stmt.prove()

    return permuted_private_key, nizk


def verify_key_permutation(public_key: petlib.ec.EcPt, permuted_public_key: petlib.ec.EcPt, nizk: NIZK) -> None:
    k_s = zksk.Secret(name="k_s")
    stmt = zksk.DLRep(permuted_public_key, k_s * public_key)
    if not stmt.verify(nizk):
        raise ProofFailedException("nizk verification failed")
