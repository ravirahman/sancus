import argparse
import logging
from datetime import timedelta
from decimal import Decimal
from threading import Lock
from typing import TYPE_CHECKING, List, Tuple

from common.utils.managed_thread_pool import ManagedThreadPool
from hexbytes.main import HexBytes
from protobufs.account_pb2 import AccountType

from utils.constants import MAX_BTC_WORKERS
from utils.runner import Account, Runner, User

if TYPE_CHECKING:
    from concurrent.futures import Future  # pylint: disable=ungrouped-imports

LOGGER = logging.getLogger(__name__)

MAX_WORKERS = 10  # don't want to overload the blockchain nodes and database too hard


def experiment() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("num_users", type=int)
    args = parser.parse_args()
    num_users = args.num_users
    with Runner(
        f"e1-num_users-{num_users}",
        account_anonymity_set_size=2,
        deposit_key_decoy_set_size=2,
    ) as runner:
        mutex = Lock()

        admin_user = runner.create_admin_user()
        for account_id in admin_user.account_id_to_account.keys():
            runner.make_deposit_key(admin_user, account_id)

        def create_user_and_keys() -> None:
            user = runner.create_user()
            for account_id in user.account_id_to_account.keys():
                runner.make_deposit_key(user, account_id)

        with ManagedThreadPool(MAX_WORKERS) as pool:
            for _ in range(num_users):
                pool(create_user_and_keys)

        runner.ensure_block_processed("ETH", timeout=timedelta(minutes=1))
        runner.ensure_block_processed("GUSD", timeout=timedelta(minutes=1))
        runner.ensure_block_processed("BTC", timeout=timedelta(minutes=1))
        # running the audit in the background as it'll take ~ 30 minutes to complete
        # with ManagedThreadPool(max_workers=1) as first_audit_thread_pool:

        #     def bound_audit() -> None:
        #         runner.audit(timeout=timedelta(minutes=60))

        #     first_audit_thread_pool(bound_audit)  # start the first audit in the background

        currencies_and_txn_hashes: List[Tuple[str, HexBytes]] = []

        with ManagedThreadPool(MAX_WORKERS) as eth_pool, ManagedThreadPool(MAX_BTC_WORKERS) as btc_pool:
            for user in [admin_user, admin_user, *runner.users]:
                # want the exchange to be solvent at the end regardless of exchange rates
                amount = Decimal("10") if user == admin_user else Decimal("0.05")
                for account in user.account_id_to_account.values():

                    def do_deposit(account: Account = account, amount: Decimal = amount) -> None:
                        def underlying() -> None:
                            txn_hash = runner.deposit_into_account(account, amount)
                            LOGGER.info(
                                "Made deposit of currency %s with txn hash %s", account.currency, txn_hash.hex()
                            )
                            with mutex:
                                currencies_and_txn_hashes.append((account.currency, txn_hash))

                        runner.try_repeat_timeout(underlying, timeout=timedelta(minutes=5))

                    if account.currency in ("GUSD", "ETH"):
                        eth_pool(do_deposit)
                    elif account.currency == "BTC":
                        btc_pool(do_deposit)
                    else:
                        raise ValueError("Invalid currency")

        max_block_to_currency = {currency: 0 for currency in ("GUSD", "ETH", "BTC")}
        # doing this single threaded to avoid hammering the blockchain nodoes
        for currency, txn_hash in currencies_and_txn_hashes:
            block_number = runner.wait_for_tx(currency, txn_hash)
            max_block_to_currency[currency] = max(
                max_block_to_currency[currency], runner.wait_for_tx(currency, txn_hash)
            )

        # sleeping so we have the deposits hit the chain and we will be able to process them
        LOGGER.info("Waiting for the backend to catch up with the chain and process deposits")
        for currency, block_number in max_block_to_currency.items():
            runner.ensure_block_processed(currency, minimum_block_number=block_number, timeout=timedelta(minutes=60))

        withdrawal_addresses: List[str] = []
        withdrawal_amount = Decimal("0.03")
        withdrawal_currency = "ETH"

        with ManagedThreadPool(MAX_BTC_WORKERS) as pool:
            for user in runner.users:
                if user.username == "admin":
                    LOGGER.info("Skipping exchange and withdrawal for admin user")
                    continue

                def do_withdrawals_and_exchanges(user: User = user) -> None:
                    LOGGER.info("Doing exchange for user %s", user.username)
                    runner.exchange(
                        user,
                        user.currency_and_account_type_to_accounts["ETH", AccountType.DEPOSIT_ACCOUNT][0].account_id,
                        user.currency_and_account_type_to_accounts["GUSD", AccountType.DEPOSIT_ACCOUNT][0].account_id,
                        Decimal("0.05"),
                    )
                    dest_address = runner.withdraw(
                        user,
                        user.currency_and_account_type_to_accounts[withdrawal_currency, AccountType.DEPOSIT_ACCOUNT][
                            0
                        ].account_id,
                        withdrawal_amount,
                    )
                    LOGGER.info("Finished withdrawal for user %s; dest address %s", user.username, dest_address)
                    with mutex:
                        withdrawal_addresses.append(dest_address)

                pool(do_withdrawals_and_exchanges)

        for dest_address in withdrawal_addresses:
            # there could be a shitton of blocks to process
            LOGGER.info("Waiting for withdrawal to %s to hit the chain", dest_address)
            runner.wait_for_withdrawal(
                withdrawal_currency, dest_address, withdrawal_amount, timeout=timedelta(minutes=120)
            )
        # adding 5 blocks to give time for decoy transactions to go through as well
        eth_block = runner.get_latest_eth_block_number() + 5
        btc_block = runner.get_latest_btc_block_number() + 5
        LOGGER.info("Waiting for blocks to be processed to ensure that withdrawals will be reconciled")
        runner.ensure_block_processed("ETH", timeout=timedelta(minutes=120), minimum_block_number=eth_block)
        runner.ensure_block_processed("GUSD", timeout=timedelta(minutes=3), minimum_block_number=eth_block)
        runner.ensure_block_processed("BTC", timeout=timedelta(minutes=120), minimum_block_number=btc_block)
        # wait for the first audit before completing the second one
        LOGGER.info("Starting the final audit")
        runner.audit(timeout=timedelta(minutes=240))


if __name__ == "__main__":
    experiment()
