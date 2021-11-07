import logging
from datetime import timedelta
from decimal import Decimal
from typing import List, Tuple

from hexbytes.main import HexBytes
from protobufs.account_pb2 import AccountType

from utils.runner import Runner

LOGGER = logging.getLogger(__name__)


def experiment() -> None:
    with Runner(
        "basic_transactions",
        account_anonymity_set_size=5,
        deposit_key_decoy_set_size=5,
    ) as runner:
        admin_user = runner.create_admin_user()
        user = runner.create_user()
        for account_id in user.account_id_to_account.keys():
            runner.make_deposit_key(user, account_id)

        for account_id in admin_user.account_id_to_account.keys():
            runner.make_deposit_key(admin_user, account_id)

        runner.ensure_block_processed("ETH", timeout=timedelta(minutes=3))
        runner.ensure_block_processed("GUSD", timeout=timedelta(minutes=3))
        runner.ensure_block_processed("BTC", timeout=timedelta(minutes=3))
        runner.audit()

        currencies_and_txn_hashes: List[Tuple[str, HexBytes]] = []
        for account in user.account_id_to_account.values():
            txn_hash = runner.deposit_into_account(account, Decimal("0.1"))
            currencies_and_txn_hashes.append((account.currency, txn_hash))
        for account in admin_user.account_id_to_account.values():
            # doing some deposits in admin so we will be solvent
            txn_hash = runner.deposit_into_account(account, Decimal("0.1"))
            currencies_and_txn_hashes.append((account.currency, txn_hash))

        max_block_to_currency = {currency: 0 for currency in ("GUSD", "ETH", "BTC")}

        for currency, txn_hash in currencies_and_txn_hashes:
            max_block_to_currency[currency] = max(
                max_block_to_currency[currency], runner.wait_for_tx(currency, txn_hash)
            )

        # sleeping so we have the deposits hit the chain and we will be able to process them
        LOGGER.info("Waiting for the backend to catch up with the chain and process deposits")
        for currency, block_number in max_block_to_currency.items():
            runner.ensure_block_processed(currency, minimum_block_number=block_number, timeout=timedelta(minutes=30))

        runner.exchange(
            user,
            user.currency_and_account_type_to_accounts["ETH", AccountType.DEPOSIT_ACCOUNT][0].account_id,
            user.currency_and_account_type_to_accounts["GUSD", AccountType.DEPOSIT_ACCOUNT][0].account_id,
            Decimal("0.05"),
        )
        withdrawal_currency = "ETH"
        withdrawal_amount = Decimal("0.03")
        dest_address = runner.withdraw(
            user,
            user.currency_and_account_type_to_accounts[withdrawal_currency, AccountType.DEPOSIT_ACCOUNT][0].account_id,
            withdrawal_amount,
        )
        runner.wait_for_withdrawal(withdrawal_currency, dest_address, withdrawal_amount, timeout=timedelta(minutes=30))
        # adding 5 blocks to give time for decoy transactions to go through as well
        eth_block = runner.get_latest_eth_block_number() + 5
        btc_block = runner.get_latest_btc_block_number() + 5
        LOGGER.info("Waiting for blocks to be processed to ensure that withdrawals will be reconciled")
        runner.ensure_block_processed("ETH", timeout=timedelta(minutes=120), minimum_block_number=eth_block)
        runner.ensure_block_processed("GUSD", timeout=timedelta(minutes=3), minimum_block_number=eth_block)
        runner.ensure_block_processed("BTC", timeout=timedelta(minutes=120), minimum_block_number=btc_block)

        runner.audit()


if __name__ == "__main__":
    experiment()
