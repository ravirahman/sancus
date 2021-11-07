import unittest
from typing import cast

import grpc
import web3
from eth_account.account import Account as ETHAccount
from eth_keys import keys
from web3.types import TxReceipt

from backend.backend import Backend
from tests.base import BaseBackendTestCase
from tests.fixtures import MAIN_ETH_ACCOUNT, EthFixturesContainer


class TestETHClient(BaseBackendTestCase):
    backend: Backend
    w3: web3.Web3
    channel: grpc.Channel
    start_block: int
    num_confirmations: int
    fixture_container: EthFixturesContainer

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.w3 = cls.backend.eth_client._w3  # pylint: disable=protected-access
        start_block = cls.backend.eth_client.start_block_number
        cls.start_block = start_block
        cls.num_confirmations = cls.backend.eth_client._num_confirmations  # pylint: disable=protected-access
        num_tests = len(list(filter(lambda x: x.startswith("test_"), dir(cls))))
        cls.fixture_container = EthFixturesContainer(cls.backend.eth_client, num_tests)

    def setUp(self) -> None:
        super().setUp()
        self.eth_fixture = self.fixture_container()

    def test_get_latest_block_number_from_chain(self) -> None:
        latest_block_number = self.backend.eth_client.get_latest_block_number_from_chain()
        self.assertGreaterEqual(latest_block_number, self.eth_fixture.eth2_tx_receipt.blockNumber)

    def test_get_public_key(self) -> None:
        nonce = self.w3.eth.get_transaction_count(self.eth_fixture.address)

        account = ETHAccount.from_key(self.eth_fixture.private_key)  # pylint: disable=no-value-for-parameter

        withdrawal_tx = account.sign_transaction(
            {
                "from": self.eth_fixture.address,
                "to": MAIN_ETH_ACCOUNT,
                "value": 1,
                "gas": 21_000,
                "gasPrice": 2,
                "nonce": nonce,
                "chainId": self.backend.eth_client._chain_id,  # pylint: disable=protected-access
            }
        )
        withdrawal_tx_hash = self.w3.eth.send_raw_transaction(withdrawal_tx.rawTransaction)
        tx_receipt = cast(TxReceipt, self.w3.eth.waitForTransactionReceipt(withdrawal_tx_hash))
        public_key = self.backend.eth_client.get_public_key(tx_receipt.transactionHash.hex())
        expected_public_key = keys.PrivateKey(account.key).public_key.to_bytes()
        self.assertEqual(public_key, expected_public_key)

    def test_get_gas_price(self) -> None:
        gas_price = self.backend.eth_client._get_gas_price()  # pylint: disable=protected-access
        self.assertTrue(isinstance(gas_price, int))


if __name__ == "__main__":
    unittest.main()
