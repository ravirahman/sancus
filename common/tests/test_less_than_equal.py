import unittest
from unittest import TestCase

from petlib.bn import Bn

from common.constants import (
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
)
from common.utils.zk.less_than_equal import (
    generate_lte_commitment,
    verify_lte_commitment,
)


class TestLTECommitment(TestCase):
    def setUp(self) -> None:
        self.lhs_amount = Bn(2) ** 65 + 1
        self.rhs_amount = Bn(2) ** 66 + 7
        self.lhs_random = SECP256K1_ORDER.random()
        self.rhs_random = SECP256K1_ORDER.random()
        self.lhs_commitment = self.lhs_amount * SECP256K1_GENERATOR + self.lhs_random * SECP256K1_ALTERNATIVE_GENERATOR
        self.rhs_commitment = self.rhs_amount * SECP256K1_GENERATOR + self.rhs_random * SECP256K1_ALTERNATIVE_GENERATOR

    def _run_test(self) -> None:
        nizk = generate_lte_commitment(self.lhs_amount, self.lhs_random, self.rhs_amount, self.rhs_random)
        verify_lte_commitment(self.lhs_commitment, self.rhs_commitment, nizk)

    def test_lte_commitment(self) -> None:
        self._run_test()


if __name__ == "__main__":
    unittest.main()
