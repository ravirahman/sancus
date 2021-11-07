import unittest
from decimal import Decimal
from typing import cast

import grpc
import web3
from common.constants import Blockchain, Currency
from eth_account.account import Account as ETHAccount
from hexbytes.main import HexBytes
from web3.types import TxReceipt

from auditor.auditor import Auditor
from auditor.sql.key_currency_block import KeyCurrencyBlock
from tests.base import BaseAuditorTestCase
from tests.fixtures import (
    ETH1_AMOUNT,
    ETH2_AMOUNT,
    GUSD1_AMOUNT,
    GUSD2_AMOUNT,
    MAIN_ETH_ACCOUNT,
    generate_eth_fixture,
    wait_for_eth_block,
)

GAS_PRICE = 18
CHAIN_ID = 58


class TestETHClient(BaseAuditorTestCase):
    auditor: Auditor
    w3: web3.Web3
    channel: grpc.Channel

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.w3 = cls.auditor.eth_client._w3  # pylint: disable=protected-access

    def setUp(self) -> None:
        super().setUp()
        self.eth_fixture = generate_eth_fixture(self.auditor.eth_client, HexBytes(self.private_key_bn.binary()))

    def test_key_currency_block(self) -> None:
        # create a withdrawal
        withdrawn_amount_cents = 3
        withdraw_amount_gusd = Decimal(withdrawn_amount_cents) / Decimal("100")
        tx_params = (
            self.auditor.eth_client._stablecoin_to_contract[Currency.GUSD]  # pylint: disable=protected-access
            .functions.transfer(MAIN_ETH_ACCOUNT, withdrawn_amount_cents)
            .buildTransaction(
                {
                    "gas": 200_000,
                    "gasPrice": GAS_PRICE,
                    "nonce": 0,
                    "chainId": CHAIN_ID,  # pylint: disable=protected-access
                }
            )
        )

        account = ETHAccount.from_key(self.eth_fixture.private_key)  # pylint: disable=no-value-for-parameter
        gusd_signed_tx = account.sign_transaction(tx_params)
        gusd_txn_hash = self.w3.eth.send_raw_transaction(gusd_signed_tx.rawTransaction)
        gusd_tx3receipt = cast(TxReceipt, self.w3.eth.waitForTransactionReceipt(gusd_txn_hash))
        gusd_tx3_block_number = gusd_tx3receipt.blockNumber
        wait_for_eth_block(self.auditor.eth_client, gusd_tx3_block_number)
        gusd_gas_costs = self.auditor.eth_client.wei_to_eth(gusd_tx3receipt.gasUsed * GAS_PRICE)

        withdrawn_amount_wei = 3

        eth_tx_params = {
            "to": MAIN_ETH_ACCOUNT,
            "value": withdrawn_amount_wei,
            "gas": 21000,
            "gasPrice": GAS_PRICE,
            "nonce": 1,
            "chainId": CHAIN_ID,  # pylint: disable=protected-access
        }
        total_debit = self.auditor.eth_client.wei_to_eth(withdrawn_amount_wei + 21000 * GAS_PRICE)
        eth_signed_tx = account.sign_transaction(eth_tx_params)
        eth_txn_hash = self.w3.eth.send_raw_transaction(eth_signed_tx.rawTransaction)
        eth_tx3receipt = cast(TxReceipt, self.w3.eth.waitForTransactionReceipt(eth_txn_hash))
        eth_tx3_block_number = eth_tx3receipt.blockNumber

        for block_number in range(self.eth_start_block, eth_tx3_block_number + 1):
            self.auditor.blockchain_client.process_block(Blockchain.ETH, block_number)
            self.auditor.blockchain_client.process_block(Blockchain.ETH, block_number)
        with self.auditor.sessionmaker() as session:
            kcb_gusd_start = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.eth_start_block - 1,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.GUSD,
                )
                .one()
            )
            self.assertEqual(kcb_gusd_start.cumulative_tracked_deposit_amount, Decimal("0"))
            self.assertEqual(kcb_gusd_start.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_gusd_start.withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_gusd_start.deposit_amount, Decimal("0"))

            kcb_eth_start = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.eth_start_block - 1,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(kcb_eth_start.cumulative_tracked_deposit_amount, Decimal("0"))
            self.assertEqual(kcb_eth_start.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_eth_start.withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_eth_start.deposit_amount, Decimal("0"))

            kcb_gusd_1 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.eth_fixture.gusd1_tx_receipt.blockNumber,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.GUSD,
                )
                .one()
            )
            self.assertEqual(kcb_gusd_1.cumulative_tracked_deposit_amount, GUSD1_AMOUNT)
            self.assertEqual(kcb_gusd_1.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_gusd_1.withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_gusd_1.deposit_amount, GUSD1_AMOUNT)

            kcb_eth_1 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.eth_fixture.eth1_tx_receipt.blockNumber,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(kcb_eth_1.cumulative_tracked_deposit_amount, ETH1_AMOUNT)
            self.assertEqual(kcb_eth_1.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_eth_1.withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_eth_1.deposit_amount, ETH1_AMOUNT)

            kcb_gusd_2 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.eth_fixture.gusd2_tx_receipt.blockNumber,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.GUSD,
                )
                .one()
            )
            self.assertEqual(kcb_gusd_2.cumulative_tracked_deposit_amount, GUSD1_AMOUNT + GUSD2_AMOUNT)
            self.assertEqual(kcb_gusd_2.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_gusd_2.withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_gusd_2.deposit_amount, GUSD2_AMOUNT)

            kcb_eth_2 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.eth_fixture.eth2_tx_receipt.blockNumber,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.ETH,
                )
                .one()
            )
            self.assertEqual(kcb_eth_2.cumulative_tracked_deposit_amount, ETH1_AMOUNT + ETH2_AMOUNT)
            self.assertEqual(kcb_eth_2.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_eth_2.withdrawal_amount, Decimal("0"))  # greater than 0 since there was the gas
            self.assertEqual(kcb_eth_2.deposit_amount, ETH2_AMOUNT)

            gusd_kcb_3 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == gusd_tx3_block_number,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.GUSD,
                )
                .one()
            )

            self.assertEqual(gusd_kcb_3.cumulative_tracked_deposit_amount, GUSD1_AMOUNT + GUSD2_AMOUNT)
            self.assertEqual(gusd_kcb_3.cumulative_tracked_withdrawal_amount, withdraw_amount_gusd)
            self.assertEqual(gusd_kcb_3.withdrawal_amount, withdraw_amount_gusd)
            self.assertEqual(gusd_kcb_3.deposit_amount, Decimal("0"))

            eth_kcb_3 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == eth_tx3_block_number,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.ETH,
                )
                .one()
            )

            self.assertEqual(eth_kcb_3.cumulative_tracked_deposit_amount, ETH1_AMOUNT + ETH2_AMOUNT)
            self.assertEqual(eth_kcb_3.cumulative_tracked_withdrawal_amount, total_debit + gusd_gas_costs)
            self.assertEqual(eth_kcb_3.withdrawal_amount, total_debit)
            self.assertEqual(eth_kcb_3.deposit_amount, Decimal("0"))


if __name__ == "__main__":
    unittest.main()
