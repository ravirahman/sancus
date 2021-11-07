import argparse
import logging
from datetime import timedelta
from decimal import Decimal
from threading import Lock
from typing import TYPE_CHECKING, List, Tuple

from common.utils.managed_thread_pool import ManagedThreadPool
from hexbytes.main import HexBytes
from protobufs.account_pb2 import AccountType

from utils.constants import MAX_BTC_WORKERS, MAX_ETH_WORKERS
from utils.runner import Runner, User

if TYPE_CHECKING:
    from concurrent.futures import Future  # pylint: disable=ungrouped-imports

LOGGER = logging.getLogger(__name__)

MAX_WORKERS = 10  # don't want to overload the blockchain nodes and database too hard

NUM_ACCOUNTS_FOR_USER = 125
NUM_DEPOSIT_KEYS = 125
TOTAL_NUM_DEPOSITS = 125


def experiment() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("account_anonymity_set_size", type=int, choices=[1, 5, 25, 75, 125])
    args = parser.parse_args()
    account_anonymity_set_size = args.account_anonymity_set_size
    with Runner(
        f"e5_anonymity_exchanges-{account_anonymity_set_size}",
        account_anonymity_set_size=account_anonymity_set_size,
        deposit_key_decoy_set_size=0,
    ) as runner:
        mutex = Lock()

        admin_user = runner.create_admin_user()

        user = runner.create_user()

        def make_accounts() -> None:
            runner.make_account(user, "BTC", AccountType.DEPOSIT_ACCOUNT)
            runner.make_account(user, "ETH", AccountType.DEPOSIT_ACCOUNT)

        def make_deposit_key() -> None:
            for account_id in user.account_id_to_account.keys():
                runner.make_deposit_key(user, account_id)

        with ManagedThreadPool(MAX_WORKERS) as pool:
            for _ in range(NUM_ACCOUNTS_FOR_USER):
                pool(make_accounts)

        with ManagedThreadPool(MAX_WORKERS) as pool:
            pool(make_deposit_key)

        runner.ensure_block_processed("ETH", timeout=timedelta(minutes=1))
        runner.ensure_block_processed("GUSD", timeout=timedelta(minutes=1))
        runner.ensure_block_processed("BTC", timeout=timedelta(minutes=1))

        # LOGGER.info("Starting the first audit")
        # runner.audit(timeout=timedelta(minutes=240))

        admin_amount = Decimal("10000.0")
        amount = Decimal("0.01")
        num_deposits_per_key = TOTAL_NUM_DEPOSITS // NUM_DEPOSIT_KEYS

        currencies_and_txn_hashes: List[Tuple[str, HexBytes]] = []

        with ManagedThreadPool(MAX_ETH_WORKERS) as eth_pool, ManagedThreadPool(MAX_BTC_WORKERS) as btc_pool:
            for currency in ["ETH", "GUSD", "BTC"]:
                for account in admin_user.currency_and_account_type_to_accounts[
                    (currency, AccountType.DEPOSIT_ACCOUNT)
                ]:
                    for address in account.deposit_addresses:

                        def do_deposit_admin(address: str = address, currency: str = currency) -> None:
                            def underlying() -> None:
                                txn_hash = runner.deposit(address, currency, admin_amount)
                                LOGGER.info("Made deposit of currency %s with txn hash %s", currency, txn_hash.hex())
                                with mutex:
                                    currencies_and_txn_hashes.append((currency, txn_hash))

                            runner.try_repeat_timeout(underlying, timeout=timedelta(minutes=5))

                        for _ in range(100):
                            if account.currency in ("GUSD", "ETH"):
                                eth_pool(do_deposit_admin)
                            elif account.currency == "BTC":
                                btc_pool(do_deposit_admin)
                            else:
                                raise ValueError("Invalid currency")

        with ManagedThreadPool(MAX_BTC_WORKERS) as btc_pool:
            for user in [*runner.users]:
                for account in user.currency_and_account_type_to_accounts[("BTC", AccountType.DEPOSIT_ACCOUNT)]:
                    for address in account.deposit_addresses:
                        for _ in range(num_deposits_per_key):

                            def do_deposit(address: str = address, currency: str = account.currency) -> None:
                                def underlying() -> None:
                                    txn_hash = runner.deposit(address, currency, amount)
                                    LOGGER.info(
                                        "Made deposit of currency %s with txn hash %s", currency, txn_hash.hex()
                                    )
                                    with mutex:
                                        currencies_and_txn_hashes.append((currency, txn_hash))

                                runner.try_repeat_timeout(underlying, timeout=timedelta(minutes=5))

                            btc_pool(do_deposit)

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

        # wait for the first audit before completing the second one
        LOGGER.info("Starting the First Audit")
        runner.audit(timeout=timedelta(minutes=240))

        with ManagedThreadPool(MAX_WORKERS) as pool:
            btc_accounts = user.currency_and_account_type_to_accounts[("BTC", AccountType.DEPOSIT_ACCOUNT)]
            eth_accounts = user.currency_and_account_type_to_accounts[("ETH", AccountType.DEPOSIT_ACCOUNT)]

            for (btc_account, eth_account) in zip(btc_accounts, eth_accounts):
                btc_account_id = btc_account.account_id
                eth_account_id = eth_account.account_id

                def do_exchange(
                    user: User = user,
                    from_account_id: bytes = btc_account_id,
                    to_account_id: bytes = eth_account_id,
                    amount: Decimal = amount,
                ) -> None:
                    def underlying() -> None:
                        runner.exchange(user, from_account_id, to_account_id, amount)
                        LOGGER.info(
                            "Made exchange of %s from account %s to account %s for user %s",
                            amount,
                            from_account_id,
                            to_account_id,
                            user,
                        )

                    runner.try_repeat_timeout(underlying, timeout=timedelta(minutes=5))

                pool(do_exchange)

        LOGGER.info("Starting the final audit")
        runner.audit(timeout=timedelta(minutes=240))


if __name__ == "__main__":
    experiment()
