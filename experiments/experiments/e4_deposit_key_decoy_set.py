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
from utils.runner import Runner

if TYPE_CHECKING:
    from concurrent.futures import Future  # pylint: disable=ungrouped-imports

LOGGER = logging.getLogger(__name__)

MAX_WORKERS = 10  # don't want to overload the blockchain nodes and database too hard

NUM_ACCOUNTS_FOR_USER = 125
NUM_DEPOSIT_KEYS = 125
TOTAL_NUM_DEPOSITS = 625


def experiment() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("decoy_set_size", type=int, choices=[1, 5, 25, 75, 125])
    args = parser.parse_args()
    decoy_set_size = args.decoy_set_size
    with Runner(
        f"e4_deposit_key_decoy_set-{decoy_set_size}",
        account_anonymity_set_size=0,
        deposit_key_decoy_set_size=decoy_set_size,
    ) as runner:
        mutex = Lock()

        user = runner.create_user()

        def make_accounts() -> None:
            runner.make_account(user, "ETH", AccountType.DEPOSIT_ACCOUNT)
            runner.make_account(user, "GUSD", AccountType.DEPOSIT_ACCOUNT)
            runner.make_account(user, "BTC", AccountType.DEPOSIT_ACCOUNT)

        def make_deposit_keys() -> None:
            for account_id in user.account_id_to_account.keys():
                runner.make_deposit_key(user, account_id)

        with ManagedThreadPool(MAX_WORKERS) as pool:
            for _ in range(NUM_ACCOUNTS_FOR_USER - 1):
                pool(make_accounts)

        with ManagedThreadPool(MAX_WORKERS) as pool:
            pool(make_deposit_keys)

        runner.ensure_block_processed("ETH", timeout=timedelta(minutes=1))
        runner.ensure_block_processed("GUSD", timeout=timedelta(minutes=1))
        runner.ensure_block_processed("BTC", timeout=timedelta(minutes=1))

        LOGGER.info("Starting the first audit")
        runner.audit(timeout=timedelta(minutes=240))

        amount = Decimal("0.05")
        num_deposits_per_key = TOTAL_NUM_DEPOSITS // NUM_DEPOSIT_KEYS

        currencies_and_txn_hashes: List[Tuple[str, HexBytes]] = []

        with ManagedThreadPool(MAX_ETH_WORKERS) as eth_pool, ManagedThreadPool(MAX_BTC_WORKERS) as btc_pool:
            for user in [*runner.users]:
                for account in user.account_id_to_account.values():
                    currency = account.currency
                    for address in account.deposit_addresses:
                        for _ in range(num_deposits_per_key):

                            def do_deposit(address: str = address, currency: str = currency) -> None:
                                def underlying() -> None:
                                    txn_hash = runner.deposit(address, currency, amount)
                                    LOGGER.info(
                                        "Made deposit of currency %s with txn hash %s", currency, txn_hash.hex()
                                    )
                                    with mutex:
                                        currencies_and_txn_hashes.append((currency, txn_hash))

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

        # wait for the first audit before completing the second one
        LOGGER.info("Starting the final audit")
        runner.audit(timeout=timedelta(minutes=240))


if __name__ == "__main__":
    experiment()
