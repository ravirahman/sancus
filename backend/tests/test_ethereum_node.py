import unittest

import web3
from web3.middleware.geth_poa import geth_poa_middleware
from web3.providers.rpc import HTTPProvider


class TestEthereumNode(unittest.TestCase):
    w3: web3.Web3

    @classmethod
    def setUpClass(cls) -> None:
        # requires that the docker compose in infra is running
        cls.w3 = web3.Web3(HTTPProvider("http://localhost:8545"))
        cls.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    def test_send_transaction(self) -> None:
        # implicitly ensures that we control the private keys, and the geth test accounts are unlocked properly
        accounts = self.w3.eth.get_accounts()
        for account in accounts:
            bal = self.w3.eth.get_balance(account)
            genesis_account_min_balance = 1_000_000_000_000_000_000_000
            if bal > genesis_account_min_balance:
                # only want to use the genesis account that has the sufficiently large initial balance
                self.w3.eth.send_transaction(
                    {"from": account, "to": "0xc0ffee254729296a45a3885639AC7E10F9d54979", "value": 1}
                )


if __name__ == "__main__":
    unittest.main()
