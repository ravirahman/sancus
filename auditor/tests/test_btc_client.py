import unittest
from decimal import Decimal
from typing import Optional

import grpc
from bitcoin.core import (
    COIN,
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    b2x,
)
from bitcoin.core.script import SIGHASH_ALL, CScript, SignatureHash
from bitcoin.core.scripteval import SCRIPT_VERIFY_P2SH, VerifyScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from common.constants import Blockchain, Currency
from hexbytes.main import HexBytes

from auditor.auditor import Auditor
from auditor.sql.key_currency_block import KeyCurrencyBlock
from tests.base import BaseAuditorTestCase
from tests.fixtures import (
    BTC_AMOUNT_1,
    BTC_AMOUNT_2,
    generate_btc_fixture,
    wait_for_bitcoin_tx,
)


class TestBTCClient(BaseAuditorTestCase):
    auditor: Auditor
    channel: grpc.Channel

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()

    def setUp(self) -> None:
        super().setUp()
        self.btc_fixture = generate_btc_fixture(HexBytes(self.private_key_bn.binary()))

    def test_key_currency_block(self) -> None:
        # create a withdrawal
        withdraw_amount = Decimal("0.02")
        tx1id = self.btc_fixture.tx_1.tx.GetTxid()
        tx1voutindex: Optional[int] = None
        for i, vout in enumerate(self.btc_fixture.tx_1.tx.vout):
            if str(CBitcoinAddress.from_scriptPubKey(vout.scriptPubKey)) == self.btc_fixture.address:
                tx1voutindex = i
        self.assertIsNotNone(tx1voutindex, "vout not found")
        tx_ins = [CMutableTxIn(COutPoint(tx1id, tx1voutindex))]
        tx_outs = [
            CMutableTxOut(int(withdraw_amount * COIN), CBitcoinAddress(self.btc_fixture.address).to_scriptPubKey())
        ]
        tx = CMutableTransaction(tx_ins, tx_outs)
        txin_script_pub_key = CBitcoinAddress(self.btc_fixture.address).to_scriptPubKey()
        seckey = CBitcoinSecret.from_secret_bytes(self.btc_fixture.private_key)
        sighash = SignatureHash(txin_script_pub_key, tx, 0, SIGHASH_ALL)
        sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
        tx.vin[0].scriptSig = CScript([sig, seckey.pub])
        VerifyScript(tx.vin[0].scriptSig, txin_script_pub_key, tx, 0, (SCRIPT_VERIFY_P2SH,))
        max_fee = "0"
        with self.auditor.btc_client._get_proxy() as proxy:  # pylint: disable=protected-access
            proxy.call("sendrawtransaction", b2x(tx.serialize()), max_fee)
            tx3id = HexBytes(tx.GetTxid())
            tx3receipt = wait_for_bitcoin_tx(proxy, tx3id)
        tx3_block_number = tx3receipt.blockheight

        for block_number in range(self.btc_start_block, tx3_block_number + 1):
            self.auditor.blockchain_client.process_block(Blockchain.BTC, block_number)
            self.auditor.blockchain_client.process_block(Blockchain.BTC, block_number)
        with self.auditor.sessionmaker() as session:
            kcb_btc_start = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.btc_start_block - 1,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(kcb_btc_start.cumulative_tracked_deposit_amount, Decimal("0"))
            self.assertEqual(kcb_btc_start.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_btc_start.withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_btc_start.deposit_amount, Decimal("0"))

            kcb_btc_1 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.btc_fixture.tx_1.blockheight,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(kcb_btc_1.cumulative_tracked_deposit_amount, BTC_AMOUNT_1)
            self.assertEqual(kcb_btc_1.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_btc_1.withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_btc_1.deposit_amount, BTC_AMOUNT_1)

            kcb_btc_2 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == self.btc_fixture.tx_2.blockheight,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(kcb_btc_2.cumulative_tracked_deposit_amount, BTC_AMOUNT_1 + BTC_AMOUNT_2)
            self.assertEqual(kcb_btc_2.cumulative_tracked_withdrawal_amount, Decimal("0"))
            self.assertEqual(kcb_btc_2.withdrawal_amount, Decimal("0"))  # greater than 0 since there was the gas
            self.assertEqual(kcb_btc_2.deposit_amount, BTC_AMOUNT_2)

            btc_kcb_3 = (
                session.query(KeyCurrencyBlock)
                .filter(
                    KeyCurrencyBlock.block_number == tx3_block_number,
                    KeyCurrencyBlock.key_uuid == self.key_uuid,
                    KeyCurrencyBlock.currency == Currency.BTC,
                )
                .one()
            )

            self.assertEqual(btc_kcb_3.cumulative_tracked_deposit_amount, BTC_AMOUNT_1 + BTC_AMOUNT_2 + withdraw_amount)
            self.assertEqual(btc_kcb_3.cumulative_tracked_withdrawal_amount, BTC_AMOUNT_1)
            self.assertEqual(btc_kcb_3.withdrawal_amount, BTC_AMOUNT_1)
            self.assertEqual(btc_kcb_3.deposit_amount, withdraw_amount)


if __name__ == "__main__":
    unittest.main()
