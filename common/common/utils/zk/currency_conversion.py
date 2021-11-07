from fractions import Fraction
from typing import Tuple

import zksk
from petlib.bn import Bn
from petlib.ec import EcPt
from zksk.primitives.rangeproof import RangeStmt

from common.constants import (
    CURRENCY_PRECISIONS,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    Currency,
)
from common.utils.zk.exceptions import ProofFailedException


def generate_currency_conversion_commitment(
    from_currency_value: Bn,
    from_currency_random: Bn,
    to_currency_random: Bn,
    from_currency: Currency,
    to_currency: Currency,
    exchange_rate: Fraction,
) -> Tuple[Bn, zksk.base.NIZK]:
    # from_currency_value is the big number of `from_currency` the from amount being converted.
    # since it must be an integer, it is in Satoshis, cents, wei, etc...
    # from_currency_random is the secret value for the pedersen commitment involving from_currency_value
    # to_currency_random is the secret value to use for the resulting pedersen commitment.
    # result of `to_currency` = (`from_currency_value` / (CURRENCY_PRECISIONS[`from_currency`] * `exchange_rate`)).
    # exchange rate is `from_currency`/`to_currency` with units in BTC, GUSD, ETH, etc, ...
    # NOT Satoshis, cents, wei, etc... to be consistent with the values returned by the marketdata service
    exchange_rate_scaled = exchange_rate * CURRENCY_PRECISIONS[from_currency] / CURRENCY_PRECISIONS[to_currency]
    exchange_rate_numerator_bn = Bn.from_decimal(str(exchange_rate_scaled.numerator))
    exchange_rate_denominator_bn = Bn.from_decimal(str(exchange_rate_scaled.denominator))
    if from_currency_value >= 0:
        to_value = (exchange_rate_denominator_bn * from_currency_value) / exchange_rate_numerator_bn
    else:
        to_value = ((exchange_rate_denominator_bn * (from_currency_value + 1)) / exchange_rate_numerator_bn) - 1

    rate_denom_from_value = exchange_rate_denominator_bn * from_currency_value  # -10
    rate_denom_from_random = exchange_rate_denominator_bn * from_currency_random
    rate_denom_from_commitment = (
        rate_denom_from_value * SECP256K1_GENERATOR + rate_denom_from_random * SECP256K1_ALTERNATIVE_GENERATOR
    )

    rate_num_to_value = exchange_rate_numerator_bn * to_value
    rate_num_to_random = exchange_rate_numerator_bn * to_currency_random
    rate_num_to_commitment = (
        rate_num_to_value * SECP256K1_GENERATOR + rate_num_to_random * SECP256K1_ALTERNATIVE_GENERATOR
    )

    value_diff = rate_denom_from_value - rate_num_to_value
    assert value_diff >= 0, f"value_diff({value_diff}) < 0"
    assert (
        value_diff < exchange_rate_numerator_bn
    ), f"value_diff({value_diff}) >= exchange_rate_numerator_bn({exchange_rate_numerator_bn})"
    r_diff = rate_denom_from_random - rate_num_to_random
    commitment_diff = rate_denom_from_commitment - rate_num_to_commitment
    assert commitment_diff == value_diff * SECP256K1_GENERATOR + r_diff * SECP256K1_ALTERNATIVE_GENERATOR

    value_diff_secret = zksk.Secret(value_diff, "value_diff")
    random_diff_secret = zksk.Secret(r_diff, "r_diff")
    diff_stmt = zksk.DLRep(
        commitment_diff, value_diff_secret * SECP256K1_GENERATOR + random_diff_secret * SECP256K1_ALTERNATIVE_GENERATOR
    )
    combined_stmt = diff_stmt
    if exchange_rate != Fraction("1"):
        range_stmt = RangeStmt(
            commitment_diff,
            g=SECP256K1_GENERATOR,
            h=SECP256K1_ALTERNATIVE_GENERATOR,
            a=Bn(0),
            b=exchange_rate_numerator_bn,
            x=value_diff_secret,
            r=random_diff_secret,
        )
        combined_stmt &= range_stmt
    # combined_stmt = from_stmt
    nizk = combined_stmt.prove()
    assert combined_stmt.verify(nizk)
    return to_value, nizk


def verify_currency_conversion_commitment(
    from_currency_commitment: EcPt,
    to_currency_commitment: EcPt,
    from_currency: Currency,
    to_currency: Currency,
    exchange_rate: Fraction,
    nizk: zksk.base.NIZK,
) -> None:
    exchange_rate_scaled = exchange_rate * CURRENCY_PRECISIONS[from_currency] / CURRENCY_PRECISIONS[to_currency]
    exchange_rate_numerator_bn = Bn.from_decimal(str(exchange_rate_scaled.numerator))
    exchange_rate_denominator_bn = Bn.from_decimal(str(exchange_rate_scaled.denominator))

    rate_denom_from_commitment = exchange_rate_denominator_bn * from_currency_commitment
    rate_num_to_commitment = exchange_rate_numerator_bn * to_currency_commitment
    commitment_diff = rate_denom_from_commitment - rate_num_to_commitment
    value_diff_secret = zksk.Secret(name="value_diff")
    random_diff_secret = zksk.Secret(name="r_diff")
    diff_stmt = zksk.DLRep(
        commitment_diff, value_diff_secret * SECP256K1_GENERATOR + random_diff_secret * SECP256K1_ALTERNATIVE_GENERATOR
    )
    combined_stmt = diff_stmt
    if exchange_rate != Fraction("1"):
        range_stmt = RangeStmt(
            commitment_diff,
            g=SECP256K1_GENERATOR,
            h=SECP256K1_ALTERNATIVE_GENERATOR,
            a=Bn(0),
            b=exchange_rate_numerator_bn,
            x=value_diff_secret,
            r=random_diff_secret,
        )
        combined_stmt &= range_stmt

    if not combined_stmt.verify(nizk):
        raise ProofFailedException()
