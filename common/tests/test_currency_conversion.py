import unittest
from decimal import Decimal
from fractions import Fraction
from unittest import TestCase

from petlib.bn import Bn

from common.constants import (
    CURRENCY_PRECISIONS,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
    Currency,
)
from common.utils.zk.currency_conversion import (
    generate_currency_conversion_commitment,
    verify_currency_conversion_commitment,
)


class TestCurrencyConversionCommitment(TestCase):
    def setUp(self) -> None:
        self.from_currency = Currency.ETH
        self.to_currency = Currency.BTC
        self.from_secret = SECP256K1_ORDER.random()
        self.to_secret = SECP256K1_ORDER.random()

    def _run_test(self, from_amount: Decimal, exchange_rate: Fraction, expected_amount: Bn) -> None:
        from_amount_bn = Bn.from_decimal(str(int(from_amount * CURRENCY_PRECISIONS[self.from_currency])))
        from_currency_commitment = (
            from_amount_bn * SECP256K1_GENERATOR + self.from_secret * SECP256K1_ALTERNATIVE_GENERATOR
        )
        to_amount_bn, nizk = generate_currency_conversion_commitment(
            from_amount_bn, self.from_secret, self.to_secret, self.from_currency, self.to_currency, exchange_rate
        )
        self.assertEqual(to_amount_bn, expected_amount)
        to_currency_commitment = to_amount_bn * SECP256K1_GENERATOR + self.to_secret * SECP256K1_ALTERNATIVE_GENERATOR
        verify_currency_conversion_commitment(
            from_currency_commitment, to_currency_commitment, self.from_currency, self.to_currency, exchange_rate, nizk
        )

    def test_generate_currency_conversion_commitment_zero_remainder(self) -> None:
        from_amount = Decimal("60")
        exchange_rate = Fraction(30, 1)
        expected_amount = Bn(2 * CURRENCY_PRECISIONS[self.to_currency])
        self._run_test(from_amount, exchange_rate, expected_amount)

    def test_generate_currency_conversion_commitment_positive_remainder(self) -> None:
        from_amount = Decimal("60")
        exchange_rate = Fraction(301, 9)
        expected_amount = Bn.from_decimal(
            "1794019933"
        )  # = from_amount / exchange_rate * CURRENCY_PRECISIONS[self.to_currency]
        self._run_test(from_amount, exchange_rate, expected_amount)

    def test_generate_currency_conversion_commitment_negative(self) -> None:
        from_amount = Decimal("-60")
        exchange_rate = Fraction(301, 9)
        expected_amount = Bn.from_decimal(
            "-1794019934"
        )  # = from_amount / exchange_rate * CURRENCY_PRECISIONS[self.to_currency]
        self._run_test(from_amount, exchange_rate, expected_amount)


if __name__ == "__main__":
    unittest.main()
