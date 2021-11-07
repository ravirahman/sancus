import unittest
from unittest import TestCase

from petlib.bn import Bn

from common.constants import (
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
)
from common.utils.zk.bit_commitment import generate_bit_commitment
from common.utils.zk.key_amount import (
    create_key_amount_commitment,
    verify_key_amount_commitment,
)


class TestKeyAmount(TestCase):
    def setUp(self) -> None:
        self.amount = Bn(2) ** 65 + 1
        self.v = SECP256K1_ORDER.random()
        self.t = SECP256K1_ORDER.random()
        self.x = SECP256K1_ORDER.random()
        self.Y = self.x * SECP256K1_GENERATOR

    def _run_test(self, s: bool) -> None:
        x_hat = self.x * Bn(s)
        p, l, nizk = create_key_amount_commitment(amount=self.amount, v=self.v, t=self.t, y=self.Y, x_hat=x_hat)
        l_bit_commitment, bit_commitment_nizk = generate_bit_commitment(s, self.t, self.Y)
        self.assertEqual(l, l_bit_commitment)
        self.assertEqual(p, self.amount * Bn(s) * SECP256K1_GENERATOR + self.v * SECP256K1_ALTERNATIVE_GENERATOR)
        self.assertEqual(l, Bn(s) * self.Y + self.t * SECP256K1_ALTERNATIVE_GENERATOR)
        verify_key_amount_commitment(self.amount, self.Y, p, l, nizk, bit_commitment_nizk)

    def test_key_amount_commitment_false(self) -> None:
        self._run_test(s=False)

    def test_key_amount_commitment_true(self) -> None:
        self._run_test(s=True)


if __name__ == "__main__":
    unittest.main()
