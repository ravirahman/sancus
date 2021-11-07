import unittest
from decimal import Decimal

import bitcoin
import bitcoin.rpc
from bitcoin.core import COIN


class TestBitcoinNode(unittest.TestCase):
    proxy: bitcoin.rpc.Proxy

    @classmethod
    def setUpClass(cls) -> None:
        bitcoin.SelectParams("regtest")
        service_url = "http://bitcoin:password@localhost:18444"
        cls.proxy = bitcoin.rpc.Proxy(service_url)

    def test_transact(self) -> None:
        addr = self.proxy.getnewaddress()
        self.proxy.sendtoaddress(str(addr), int(Decimal("1.09") * COIN))

    def tearDown(self) -> None:
        pass


if __name__ == "__main__":
    unittest.main()
