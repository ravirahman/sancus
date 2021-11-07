import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from csv import writer
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from queue import Queue
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    cast,
)

import bitcoin
import bitcoin.core
import bitcoin.rpc
import dotenv
import grpc
import jwt
import web3
import web3.types
from common.config import GRPCConfig
from common.utils.grpc_channel import make_grpc_channel
from common.utils.soft_webauthn_client import SoftWebauthnClient
from eth_account.account import Account as ETHAccount
from grpc_health.v1.health_pb2 import HealthCheckRequest, HealthCheckResponse
from grpc_health.v1.health_pb2_grpc import HealthStub
from hexbytes.main import HexBytes
from protobufs.institution.account_pb2 import (
    AccountResponse,
    ListAccountsRequest,
    MakeAccountRequest,
)
from protobufs.institution.account_pb2_grpc import AccountStub
from protobufs.institution.auth_pb2 import (
    MakeRegistrationChallengeRequest,
    RegisterRequest,
)
from protobufs.institution.auth_pb2_grpc import AuthStub
from protobufs.institution.deposit_pb2 import MakeDepositKeyRequest
from protobufs.institution.deposit_pb2_grpc import DepositStub
from protobufs.institution.exchange_pb2 import (
    InitiateExchangeRequest,
    ProcessExchangeRequest,
)
from protobufs.institution.exchange_pb2_grpc import ExchangeStub
from protobufs.institution.marketdata_pb2 import (
    GetLatestProcessedBlockNumberRequest,
    GetMarketExchangeRateRequest,
)
from protobufs.institution.marketdata_pb2_grpc import MarketdataStub
from protobufs.institution.withdrawal_pb2 import (
    InitiateWithdrawalRequest,
    ProcessWithdrawalRequest,
)
from protobufs.institution.withdrawal_pb2_grpc import WithdrawalStub
from protobufs.validator.auditor_pb2 import GetLatestAuditVersionRequest
from protobufs.validator.auditor_pb2_grpc import AuditorStub
from sqlalchemy import create_engine
from sqlalchemy_utils import create_database
from web3.middleware.geth_poa import geth_poa_middleware

from utils.constants import BTC_HOST, MAX_BTC_WORKERS, WEBAUTHN_ORIGIN, get_w3_provider
from utils.contract_deployer import ContractDeployer
from utils.experiment_processor import ExperimentProcessor
from utils.list_rpc import list_rpc_yield
from utils.wait_for_it import wait_for_it

if TYPE_CHECKING:
    from protobufs.account_pb2 import AccountType  # pylint: disable=ungrouped-imports


MANAGE_INFRA = False
ENABLE_PY_SPY = False

EXPERIMENTS_DIRECTORY = os.path.join(os.path.dirname(__file__), "..")

LOGGER = logging.getLogger(__name__)
ETH_DOTENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "infra", "output", "eth.env")
TResponse = TypeVar("TResponse")

if ENABLE_PY_SPY:
    _PY_SPY = shutil.which("py-spy")
    assert _PY_SPY is not None
    PY_SPY = _PY_SPY

bitcoin.SelectParams("regtest")


@dataclass
class Account:
    account_id: bytes
    account_type: int
    currency: str
    deposit_addresses: List[str]


@dataclass
class User:
    user_id: bytes
    currency_and_account_type_to_accounts: Dict[Tuple[str, int], List[Account]]
    account_id_to_account: Dict[bytes, Account]
    grpc_channel: grpc.Channel
    deposit_stub: DepositStub
    account_stub: AccountStub
    exchange_stub: ExchangeStub
    marketdata_stub: MarketdataStub
    withdrawal_stub: WithdrawalStub
    username: str


def _get_erc20_abi() -> str:
    with open(os.path.join(os.path.dirname(__file__), "erc20abi.json"), "r") as f:
        return f.read()


ERC20_ABI = _get_erc20_abi()


class Runner:
    def __init__(
        self, experiment_name: str, *, account_anonymity_set_size: int, deposit_key_decoy_set_size: int
    ) -> None:
        self.experiment_name = experiment_name
        current_time = datetime.now().isoformat()
        self.experiment_tag = f"{self.experiment_name}-{current_time.replace(':','-').replace('.','-')}"
        self.output_dir = os.path.join(os.path.dirname(__file__), "..", "results", self.experiment_name, current_time)
        os.makedirs(self.output_dir)
        logging.getLogger("__main__").setLevel(logging.DEBUG)
        logging.getLogger("experiments").setLevel(logging.DEBUG)
        logging.getLogger("utils").setLevel(logging.DEBUG)
        logging.basicConfig(
            filename=os.path.join(self.output_dir, "experiment.log"),
            filemode="x",
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        self.backend_output_dir = os.path.join(self.output_dir, "backend")
        os.makedirs(self.backend_output_dir)
        self.auditgen_output_dir = os.path.join(self.output_dir, "auditgen")
        os.makedirs(self.auditgen_output_dir)
        self.auditor_output_dir = os.path.join(self.output_dir, "auditor")
        os.makedirs(self.auditor_output_dir)
        self.infra_output_dir = os.path.join(self.output_dir, "infra")
        os.makedirs(self.infra_output_dir)
        self.profile_output_dir = os.path.join(self.output_dir, "profile")
        os.makedirs(self.profile_output_dir)
        self.audit_counter = 0

        self.btc_proxy_queue: "Queue[None]" = Queue(MAX_BTC_WORKERS)
        for _ in range(MAX_BTC_WORKERS):
            self.btc_proxy_queue.put_nowait(None)

        self.infra_stdout_file = open(os.path.join(self.infra_output_dir, "stdout.log"), "x")
        self.infra_stderr_file = open(os.path.join(self.infra_output_dir, "stderr.log"), "x")

        LOGGER.info("Waiting for the infra to spin up")
        self.infra_proc = self.create_infra()
        wait_for_it("localhost", 3306, timedelta(seconds=15))
        wait_for_it("localhost", 18444, timedelta(seconds=15))
        wait_for_it("localhost", 5001, timedelta(seconds=15))
        wait_for_it("localhost", 8545, timedelta(seconds=15))

        self.w3 = web3.Web3(provider=get_w3_provider(), middlewares=(geth_poa_middleware,))

        # ensure that we are actually connected to the ethereum node

        LOGGER.info("Attempting to get the eth block number to ensure we are connected to w3")
        self.get_latest_eth_block_number()

        self.auditor_db = f"mysql+pymysql://root:password@127.0.0.1:3306/auditor-{self.experiment_tag}"
        self.backend_db = f"mysql+pymysql://root:password@127.0.0.1:3306/backend-{self.experiment_tag}"

        def create_auditor_database() -> None:
            create_database(self.auditor_db)

        def create_backend_database() -> None:
            create_database(self.backend_db)

        # ensure that we have the databases. it takes 2-3 minutes for the docker mysql to start up
        LOGGER.info("Attempting to create the auditor db")
        self.try_repeat_timeout(create_auditor_database, timedelta(seconds=240))

        LOGGER.info("Attempting to create the backend db")
        self.try_repeat_timeout(create_backend_database, timedelta(seconds=30))

        # TODO ensure that we have the bitcoin node and ipfs node

        assert os.path.exists(ETH_DOTENV_PATH)
        dotenv.load_dotenv(ETH_DOTENV_PATH)
        self.eth_main_address = os.environ["ETH_MAIN_ADDRESS"]
        LOGGER.info("Deploying contracts")
        self.contract_deployer = ContractDeployer(self.eth_main_address)
        gusd_contract_address, audit_publisher_contract_address = self.contract_deployer.deploy_contracts()
        self.gusd_contract = self.w3.eth.contract(address=gusd_contract_address, abi=ERC20_ABI)
        eth_latest_block_number = self.get_latest_eth_block_number()
        LOGGER.info("eth start block number: %d", eth_latest_block_number)

        btc_latest_block_number = self.get_latest_btc_block_number()
        LOGGER.info("btc start block number: %d", btc_latest_block_number)
        self.sock_folder = tempfile.TemporaryDirectory()

        self.backend_sock_abspath = os.path.abspath(os.path.join(self.sock_folder.name, "backend.sock"))
        self.backend_grpc_socket = "unix://" + self.backend_sock_abspath
        LOGGER.info("running backend grpc at %s", self.backend_grpc_socket)

        self.auditor_sock_abspath = os.path.abspath(os.path.join(self.sock_folder.name, "auditor.sock"))
        self.auditor_grpc_socket = "unix://" + self.auditor_sock_abspath
        LOGGER.info("running auditor grpc at %s", self.auditor_grpc_socket)

        auditor_folder = os.path.join(self.auditor_output_dir, "audits")
        os.makedirs(auditor_folder)

        self.experiment_processor = ExperimentProcessor(
            outfile=os.path.join(self.profile_output_dir, "aggregate_data.csv"),
            btc_outfile=os.path.join(self.profile_output_dir, "btc_data.csv"),
            eth_outfile=os.path.join(self.profile_output_dir, "eth_data.csv"),
            experiment_name=self.experiment_name,
            current_time=current_time,
            w3=self.w3,
        )

        self.env_vars: Dict[str, str] = {
            "BACKEND_DB": self.backend_db,
            "BACKEND_LOG_FILE": os.path.join(self.backend_output_dir, "backend.log"),
            "BACKEND_GRPC_SOCKFILE": self.backend_grpc_socket,
            "AUDITOR_GRPC_SOCKFILE": self.auditor_grpc_socket,
            "ETH_START_BLOCK_NUMBER": str(eth_latest_block_number),
            "GUSD_CONTRACT_ADDRESS": gusd_contract_address,
            "BTC_START_BLOCK_NUMBER": str(btc_latest_block_number),
            "AUDIT_PUBLISHER_CONTRACT_ADDRESS": audit_publisher_contract_address,
            "ETH_CONTRACTS_OWNER": self.eth_main_address,
            "ETH_MAIN_ADDRESS": self.eth_main_address,
            # "GRPC_TRACE": "api,call_error,p_failure",
            "GRPC_VERBOSITY": "INFO",
            # "GRPC_STACKTRACE_MINLOGLEVEL": "INFO",
            "AUDITOR_LOG_FILE": os.path.join(self.auditor_output_dir, "auditor.log"),
            "AUDITOR_DB": self.auditor_db,
            "AUDITOR_FOLDER": auditor_folder,
            "PROFILE_DATA_FOLDER": self.profile_output_dir,
            "ACCOUNT_ANONYMITY_SET_SIZE": str(account_anonymity_set_size),
            "DEPOSIT_KEY_DECOY_SET_SIZE": str(deposit_key_decoy_set_size),
            "EXCHANGE_RATE_EPSILON": "1000000",  # effectively disable exchange rate validation
        }

        self.stopped = False
        self.users: List[User] = []
        self.soft_webauthn = SoftWebauthnClient(WEBAUTHN_ORIGIN)
        self.background_job = threading.Thread(target=self.loop)

        # let's start the docker compose
        backend_pstats = os.path.join(self.backend_output_dir, "backend-profile.svg")
        command_prefix = ["taskset", "-ac", os.environ["BACKEND_CPUS"]] if "BACKEND_CPUS" in os.environ else []
        if ENABLE_PY_SPY:
            command_prefix.extend(
                [
                    PY_SPY,
                    "record",
                    "-o",
                    backend_pstats,
                    "--rate",
                    "20",
                    "--nonblocking",
                    "--",
                ]
            )
        command = [
            *command_prefix,
            sys.executable,
            "-m",
            "utils.backend",
        ]
        LOGGER.info(
            "Starting backend with command: cd %s; %s %s",
            EXPERIMENTS_DIRECTORY,
            " ".join([f"{name}={value}" for (name, value) in self.env_vars.items()]),
            " ".join(command),
        )

        self.backend_stdout_file = open(os.path.join(self.backend_output_dir, "stdout.log"), "x")
        self.backend_stderr_file = open(os.path.join(self.backend_output_dir, "stderr.log"), "x")

        self.backend_proc = subprocess.Popen(
            command,
            cwd=EXPERIMENTS_DIRECTORY,
            stdout=self.backend_stdout_file,
            stderr=self.backend_stderr_file,
            env=self.env_vars,
            universal_newlines=True,
        )
        self.auditor_stdout_file = open(os.path.join(self.auditor_output_dir, "stdout.log"), "x")
        self.auditor_stderr_file = open(os.path.join(self.auditor_output_dir, "stderr.log"), "x")
        command_prefix = ["taskset", "-ac", os.environ["AUDITOR_CPUS"]] if "AUDITOR_CPUS" in os.environ else []
        auditor_pstats = os.path.join(self.auditor_output_dir, "auditor-profile.svg")
        auditor_cwd = os.path.join(os.path.dirname(__file__), "..", "..", "auditor")
        if ENABLE_PY_SPY:
            command_prefix.extend(
                [
                    PY_SPY,
                    "record",
                    "-o",
                    auditor_pstats,
                    "--rate",
                    "20",
                    "--nonblocking",
                    "--",
                ]
            )
        command = [
            *command_prefix,
            sys.executable,
            "-m",
            "utils.auditor",
        ]
        LOGGER.info(
            "Starting auditor with command: cd %s; %s %s",
            auditor_cwd,
            " ".join([f"{name}={value}" for (name, value) in self.env_vars.items()]),
            " ".join(command),
        )
        self.auditor_proc = subprocess.Popen(
            command,
            cwd=EXPERIMENTS_DIRECTORY,
            stdout=self.auditor_stdout_file,
            stderr=self.auditor_stderr_file,
            env=self.env_vars,
            universal_newlines=True,
        )
        LOGGER.info("Checking for backend sockfile")

        def check_for_backend_sockfile() -> None:
            if not os.path.exists(self.backend_sock_abspath):
                LOGGER.info("Waiting for backend sockfile")
                raise Exception("Waiting for backend sockfile")

        self.try_repeat_timeout(check_for_backend_sockfile, timedelta(minutes=5))
        LOGGER.info("backend sockfile exists")

        self.backend_grpc_config = GRPCConfig(
            host=self.backend_grpc_socket,
            max_workers=10,
        )

        self.unauthenticated_channel = make_grpc_channel(self.backend_grpc_config)

        self.auth_stub = AuthStub(self.unauthenticated_channel)
        self.backend_health_stub = HealthStub(self.unauthenticated_channel)
        self.marketdata_stub = MarketdataStub(self.unauthenticated_channel)

        def health_check_backend() -> None:
            request = HealthCheckRequest(service="sancus.institution.Auth")
            resp = self.backend_health_stub.Check(request)
            if resp.status != HealthCheckResponse.SERVING:
                LOGGER.info("Not yet serving backend")
                raise Exception("Not yet serving")

        self.try_repeat_timeout(health_check_backend, timedelta(seconds=10))
        LOGGER.info("Serving backend")

        def check_for_auditor_sockfile() -> None:
            if not os.path.exists(self.auditor_sock_abspath):
                LOGGER.info("Waiting for auditor sockfile")
                raise Exception("Waiting for auditor sockfile")

        self.try_repeat_timeout(check_for_auditor_sockfile, timedelta(minutes=5))
        LOGGER.info("Found auditor sockfile")

        self.auditor_grpc_config = GRPCConfig(
            host=self.auditor_grpc_socket,
            max_workers=10,
        )

        self.auditor_channel = make_grpc_channel(self.auditor_grpc_config)
        self.auditor_stub = AuditorStub(self.auditor_channel)
        self.auditor_health_stub = HealthStub(self.auditor_channel)

        def health_check_auditor() -> None:
            request = HealthCheckRequest(service="sancus.validator.Auditor")
            resp = self.auditor_health_stub.Check(request)
            if resp.status != HealthCheckResponse.SERVING:
                LOGGER.info("Not yet serving auditor")
                raise Exception("Not yet serving auditor")

        self.try_repeat_timeout(health_check_auditor, timedelta(minutes=5))
        LOGGER.info("Serving auditor")
        self.background_job.start()

    def deposit(self, address: str, currency: str, amount: Decimal) -> HexBytes:
        LOGGER.info("Depositing %s %s into %s", amount, currency, address)
        if currency == "GUSD":
            tx_params = self.gusd_contract.functions.transfer(address, int(amount * 100)).buildTransaction(
                {
                    "from": self.eth_main_address,
                }
            )
            txn_hash = self.w3.eth.send_transaction(tx_params)
            return HexBytes(txn_hash)
        if currency == "ETH":
            txn_hash = self.w3.eth.send_transaction(
                {
                    "from": self.eth_main_address,
                    "to": address,
                    "value": int(amount * 10 ** 18),
                }
            )
            return HexBytes(txn_hash)
        if currency == "BTC":
            with self.get_btc() as proxy:
                txn_hash = proxy.sendtoaddress(address, int(amount * bitcoin.core.COIN))
            return HexBytes(txn_hash)
        raise ValueError("Invalid currency")

    def wait_for_tx(self, currency: str, transaction_id: HexBytes) -> int:
        # returns the block number containing the transaction
        LOGGER.info("waiting for %s %s", currency, transaction_id.hex())
        if currency == "BTC":

            def check_for_transaction() -> int:
                with self.get_btc() as proxy:
                    tx = proxy.getrawtransaction(transaction_id, verbose=True)
                    if tx["blockhash"] is None:
                        raise Exception(f"tx {transaction_id.hex()} not in chain")
                    block_header = proxy.getblockheader(tx["blockhash"], verbose=True)
                    block_number: int = block_header["height"]
                    return block_number

        elif currency in ("GUSD", "ETH"):

            def check_for_transaction() -> int:
                tx_receipt = cast(web3.types.TxReceipt, self.w3.eth.getTransactionReceipt(transaction_id))
                block_number: int = tx_receipt.blockNumber
                return block_number

        else:
            raise ValueError(f"Unknown currency {currency}")

        block_number = self.try_repeat_timeout(check_for_transaction, timedelta(minutes=5))
        LOGGER.info("transaction %s %s has block number %d", currency, transaction_id.hex(), block_number)
        return block_number

    @staticmethod
    def make_deposit_key(user: User, account_id: bytes) -> None:
        LOGGER.info("Making deposit key for user(%s), account(%s)", user.username, account_id.hex())
        deposit_key_request = MakeDepositKeyRequest(accountId=account_id)
        deposit_key_response = user.deposit_stub.MakeDepositKey(deposit_key_request)
        user.account_id_to_account[account_id].deposit_addresses.append(deposit_key_response.depositKey.address)

    def deposit_into_account(self, account: Account, amount: Decimal) -> HexBytes:
        address = account.deposit_addresses[0]
        currency = account.currency
        return self.deposit(address, currency, amount)

    def create_admin_user(self) -> User:
        return self._create_user("admin")

    def create_user(self) -> User:
        username = f"user_{uuid.uuid4()}"
        return self._create_user(username)

    def _create_user(self, username: str) -> User:
        LOGGER.info("Creating user %s", username)
        assert self.auth_stub is not None
        registration_challenge_response = self.auth_stub.MakeRegistrationChallenge(
            MakeRegistrationChallengeRequest(username=username),
        )
        attestation = self.soft_webauthn.create_credential(registration_challenge_response.credentialRequest)
        register_response = self.auth_stub.Register(
            RegisterRequest(
                challengeNonce=registration_challenge_response.challengeRequest.nonce,
                attestation=attestation,
            )
        )
        user_jwt = register_response.jwt
        user_channel = make_grpc_channel(self.backend_grpc_config, user_jwt)
        account_stub = AccountStub(user_channel)

        account_id_to_account: Dict[bytes, Account] = {}
        currency_and_account_type_to_accounts: Dict[Tuple[str, int], List[Account]] = {}

        for account_response in list_rpc_yield(ListAccountsRequest(), account_stub.ListAccounts):
            assert isinstance(account_response, AccountResponse)
            account_id = account_response.id
            currency = account_response.currency
            account_type = account_response.accountType
            account = Account(account_id=account_id, account_type=account_type, currency=currency, deposit_addresses=[])
            if (currency, account_type) not in currency_and_account_type_to_accounts:
                currency_and_account_type_to_accounts[currency, account_type] = []
            currency_and_account_type_to_accounts[currency, account_type].append(account)
            account_id_to_account[account_id] = account

        user = User(
            user_id=bytes.fromhex(jwt.decode(user_jwt, options={"verify_signature": False})["sub"]),
            currency_and_account_type_to_accounts=currency_and_account_type_to_accounts,
            account_id_to_account=account_id_to_account,
            grpc_channel=user_channel,
            deposit_stub=DepositStub(user_channel),
            account_stub=account_stub,
            exchange_stub=ExchangeStub(user_channel),
            marketdata_stub=MarketdataStub(user_channel),
            withdrawal_stub=WithdrawalStub(user_channel),
            username=username,
        )
        self.users.append(user)
        return user

    def get_latest_block_processed(self, currency: str) -> int:
        if currency in ("GUSD", "ETH"):
            return self.marketdata_stub.GetLatestProcessedBlockNumber(
                GetLatestProcessedBlockNumberRequest(blockchain="ETH")
            ).blockNumber
        if currency == "BTC":
            return self.marketdata_stub.GetLatestProcessedBlockNumber(
                GetLatestProcessedBlockNumberRequest(blockchain="BTC")
            ).blockNumber
        raise ValueError(f"Invalid currency: {currency}")

    def ensure_block_processed(
        self,
        currency: str,
        timeout: timedelta,
        minimum_block_number: Optional[int] = None,
    ) -> None:
        # ensures that at least one block for both bitcoin and ethereum are processed
        deadline = datetime.now() + timeout

        def get_currency_block_processed() -> int:
            return self.get_latest_block_processed(currency)

        if minimum_block_number is None:
            start_block_number = self.try_repeat_timeout(get_currency_block_processed, timeout)
            minimum_block_number = start_block_number + 1
        LOGGER.info("Waiting for backend to process block %s for currency %s", minimum_block_number, currency)

        while datetime.now() < deadline:
            new_block_number = get_currency_block_processed()
            if new_block_number >= minimum_block_number:
                LOGGER.info(
                    "Backend finished processing block %s >= %s for currency %s",
                    new_block_number,
                    minimum_block_number,
                    currency,
                )
                return
            LOGGER.info(
                "Backend finished processing block %s < %s for currency %s; sleeping 1 second",
                new_block_number,
                minimum_block_number,
                currency,
            )
            time.sleep(1)
        raise Exception("Failed to process blocks before timeout")

    def exchange(self, user: User, from_account_id: bytes, to_account_id: bytes, amount: Decimal) -> None:
        LOGGER.info(
            "Exchanging %s from account %s to account %s for user %s",
            amount,
            from_account_id.hex(),
            to_account_id.hex(),
            user.username,
        )
        from_currency = user.account_id_to_account[from_account_id].currency
        to_currency = user.account_id_to_account[to_account_id].currency
        exchange_rate_request = GetMarketExchangeRateRequest(fromCurrency=from_currency, toCurrency=to_currency)
        exchange_rate_response = user.marketdata_stub.GetMarketExchangeRate(exchange_rate_request)

        initiate_exchange_request = InitiateExchangeRequest(
            exchangeRateJWT=exchange_rate_response.exchangeRateJWT,
            amount=str(amount),
            fromAccountId=from_account_id,
            toAccountId=to_account_id,
        )
        initiate_exchange_response = user.exchange_stub.InitiateExchange(initiate_exchange_request)
        exchange_assertion = self.soft_webauthn.request_assertion(
            initiate_exchange_response.challengeRequest, initiate_exchange_response.credentialRequest
        )
        process_exchange_request = ProcessExchangeRequest(
            id=initiate_exchange_response.id, assertion=exchange_assertion
        )
        user.exchange_stub.ProcessExchange(process_exchange_request)

    def withdraw(self, user: User, from_account_id: bytes, amount: Decimal) -> str:
        LOGGER.info("Withdrawing %s from account %s for user %s", amount, from_account_id.hex(), user.username)
        currency = user.account_id_to_account[from_account_id].currency
        if currency in ("ETH", "GUSD"):
            account = ETHAccount.create()  # pylint: disable=no-value-for-parameter
            destination_address = str(account.address)
        elif currency == "BTC":

            def get_address() -> str:
                # need to use the proxy, rather than doing it locally, so the address is in the wallet
                # and we can get the balance
                with self.get_btc() as proxy:
                    return str(proxy.getnewaddress())

            destination_address = self.try_repeat_timeout(get_address, timeout=timedelta(minutes=5))
        else:
            raise ValueError("invalid account currency")
        initiate_request = InitiateWithdrawalRequest(
            amount=str(amount),
            fromAccountId=from_account_id,
            destinationAddress=destination_address,
        )
        initiate_response = user.withdrawal_stub.InitiateWithdrawal(initiate_request)
        withdrawal_assertion = self.soft_webauthn.request_assertion(
            initiate_response.challengeRequest, initiate_response.credentialRequest
        )
        process_request = ProcessWithdrawalRequest(id=initiate_response.id, assertion=withdrawal_assertion)
        user.withdrawal_stub.ProcessWithdrawal(process_request)
        return destination_address

    def get_chain_balance(self, currency: str, address: str) -> Decimal:
        if currency == "ETH":

            def get_bal() -> Decimal:
                return Decimal(self.w3.eth.get_balance(address, "latest")) / Decimal(10 ** 18)

        elif currency == "GUSD":

            def get_bal() -> Decimal:
                return Decimal(
                    self.gusd_contract.functions.balanceOf(address).call(block_identifier="latest")
                ) / Decimal(10 ** 2)

        elif currency == "BTC":

            def get_bal() -> Decimal:
                with self.get_btc() as proxy:
                    return Decimal(proxy.getreceivedbyaddress(address)) / Decimal(10 ** 9)

        else:
            raise ValueError(f"Unknown currency: {currency}")
        return self.try_repeat_timeout(get_bal, timeout=timedelta(minutes=5))

    def wait_for_withdrawal(
        self,
        currency: str,
        address: str,
        amount: Decimal,
        timeout: timedelta,
    ) -> None:
        def check() -> None:
            chain_amount = self.get_chain_balance(currency, address)
            if chain_amount < amount:
                raise Exception(f"Chain amount {chain_amount} < expected amount {amount}")

        self.try_repeat_timeout(check, timeout)

    def audit(self, timeout: timedelta = timedelta(minutes=30)) -> None:
        self.audit_counter += 1  # audit versions are 1-indexed
        auditgen_output_dir = os.path.join(self.auditgen_output_dir, f"audit_{self.audit_counter}")
        auditgen_pstats = os.path.join(auditgen_output_dir, "auditgen-profile.svg")
        command_prefix = ["taskset", "-ac", os.environ["AUDITGEN_CPUS"]] if "AUDITGEN_CPUS" in os.environ else []
        check = True
        if ENABLE_PY_SPY:
            command_prefix.extend(
                [
                    PY_SPY,
                    "record",
                    "-o",
                    auditgen_pstats,
                    "--",
                ]
            )
            check = False  # there's a bug with check py-spy -- the return code isn't properly set
        command = [
            *command_prefix,
            sys.executable,
            "-m",
            "utils.auditgen",
            f"--output_directory={auditgen_output_dir}",
        ]
        LOGGER.info(
            "Auditing with command cd %s; %s %s",
            EXPERIMENTS_DIRECTORY,
            " ".join([f"{name}={value}" for (name, value) in self.env_vars.items()]),
            " ".join(command),
        )
        # call auditgen via subprocess
        # Generate, publish, and validate an audit
        os.makedirs(auditgen_output_dir)
        with open(os.path.join(auditgen_output_dir, "stdout.log"), "x") as stdout_file:
            with open(os.path.join(auditgen_output_dir, "stderr.log"), "x") as stderr_file:
                # there's an issue where py-spy changes the exit code, so currently ignoring it
                subprocess.run(
                    command,
                    cwd=EXPERIMENTS_DIRECTORY,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    env=self.env_vars,
                    universal_newlines=True,
                    check=check,
                )
        audit_version = self.audit_counter

        # wait for the audit to finish
        def check_audit_version() -> None:
            resp = self.auditor_stub.GetLatestAuditVersion(GetLatestAuditVersionRequest())
            if resp.version < audit_version:
                raise Exception(f"audit version {resp.version} < desired audit version audit_version")

        self.try_repeat_timeout(check_audit_version, timeout)

        # record the size of the auditor DB
        def record_db_size() -> None:
            db_names = {"auditor": self.auditor_db, "backend": self.backend_db}
            for name in db_names:
                statement = "SELECT table_schema, table_name, data_length, index_length FROM information_schema.tables"
                profile_data_folder = self.env_vars["PROFILE_DATA_FOLDER"]
                output_dir = os.path.join(profile_data_folder, f"{name}_db")

                engine = create_engine(db_names[name])
                with engine.connect() as con:
                    res = con.execute(statement)
                    all_tables = res.fetchall()
                    key = f"{name}-{self.experiment_tag}"
                    filtered_res = [t for t in all_tables if t[0] == key]

                if not os.path.isdir(output_dir):
                    os.makedirs(output_dir)
                with open(f"{output_dir}/{name}_db_size.csv", "a") as f:
                    writer_object = writer(f)
                    if self.audit_counter == 1:
                        writer_object.writerow(
                            ["audit_version", "table_schema", "table_name", "data_length", "index_length"]
                        )
                    for t in filtered_res:
                        writer_object.writerow([self.audit_counter] + list(t))

        self.try_repeat_timeout(record_db_size, timeout)

        LOGGER.info("Auditing %d finished", audit_version)

    @staticmethod
    def try_repeat_timeout(func: Callable[[], TResponse], timeout: timedelta) -> TResponse:
        deadline = datetime.now() + timeout
        while True:
            try:
                return func()
            except Exception as e:
                if datetime.now() < deadline:
                    # LOGGER.info("Check failed; sleeping 1 second and trying again")
                    time.sleep(1)
                    continue
                LOGGER.error("Try-repeat-timeout failed", exc_info=True)
                raise Exception("Try-repeat-timeout failed") from e

    @staticmethod
    def make_account(user: User, currency: str, account_type: "AccountType.V") -> None:
        request = MakeAccountRequest(accountType=account_type, currency=currency)
        response = user.account_stub.MakeAccount(request)
        account_id = response.accountId
        account = Account(account_id=account_id, account_type=account_type, currency=currency, deposit_addresses=[])
        user.account_id_to_account[account_id] = account
        if (currency, account_type) not in user.currency_and_account_type_to_accounts:
            user.currency_and_account_type_to_accounts[currency, account_type] = []
        user.currency_and_account_type_to_accounts[currency, account_type].append(account)

    def create_infra(self) -> "Optional[subprocess.Popen[str]]":
        if MANAGE_INFRA:
            infra_env_vars: Dict[str, str] = {}

            def conditional_merge(key: str) -> None:
                if key in os.environ:
                    infra_env_vars[key] = os.environ[key]

            conditional_merge("MYSQL_CPUS")
            conditional_merge("GETH_CPUS")
            conditional_merge("IPFS_CPUS")
            conditional_merge("BITCOIN_CORE_CPUS")
            conditional_merge("BITCOIN_MINER_CPUS")
            infra_file = os.environ.get("INFRA_COMPOSE_FILE", "docker-compose.yml")
            # stop the existing infra
            LOGGER.info("Stopping the existing infra")
            subprocess.check_call(
                [
                    "/usr/local/bin/docker-compose",
                    "-f",
                    infra_file,
                    "down",
                    "-v",
                ],
                cwd=os.path.join(os.path.dirname(__file__), "..", "..", "infra"),
                env=infra_env_vars,
                universal_newlines=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            LOGGER.info("Stopped the existing infra")
            command_prefix = ["taskset", "-ac", os.environ["INFRA_CPUS"]] if "INFRA_CPUS" in os.environ else []
            command = [
                *command_prefix,
                "/usr/local/bin/docker-compose",
                "-f",
                infra_file,
                "up",
                "--build",
            ]
            LOGGER.info("Starting infra with command %s", " ".join(command))
            return subprocess.Popen(
                command,
                cwd=os.path.join(os.path.dirname(__file__), "..", "..", "infra"),
                stdout=self.infra_stdout_file,
                stderr=self.infra_stderr_file,
                env=infra_env_vars,
                universal_newlines=True,
            )
        return None

    def get_latest_eth_block_number(self) -> int:
        def get_eth_block() -> int:
            block_number: int = self.w3.eth.block_number
            return block_number

        return self.try_repeat_timeout(get_eth_block, timedelta(seconds=30))

    def get_latest_btc_block_number(self) -> int:
        def btc_block_count() -> int:
            with self.get_btc() as proxy:
                block_count = proxy.getblockcount()
                assert isinstance(block_count, int)
                return block_count

        return self.try_repeat_timeout(btc_block_count, timedelta(seconds=60))

    @contextmanager
    def get_btc(self) -> Generator[bitcoin.rpc.Proxy, None, None]:  # type: ignore[misc]
        self.btc_proxy_queue.get(timeout=30)  # get a "Lock" for a proxy from the pool
        try:
            proxy = bitcoin.rpc.Proxy(BTC_HOST, timeout=60)
            try:
                yield proxy
            finally:
                proxy.close()
        finally:
            self.btc_proxy_queue.put_nowait(None)

    def dump_env_vars(self) -> None:
        with open(os.path.join(self.profile_output_dir, "env_vars.json"), "w") as env_vars_file:
            json.dump(self.env_vars, env_vars_file)

    def __enter__(self) -> "Runner":
        return self

    def close(self) -> None:
        LOGGER.info("Attempting an orderly shutdown")
        LOGGER.info("Dumping Envionment Variables")
        self.dump_env_vars()
        LOGGER.info("Processing Profile Data")
        self.experiment_processor.execute_script()

        LOGGER.info("Closing user channels")
        for user in self.users:
            user.grpc_channel.close()
        self.users.clear()
        LOGGER.info("Marking backend as stopped")
        self.stopped = True
        self.unauthenticated_channel.close()
        self.auditor_channel.close()
        LOGGER.info("Joining the background job")
        self.background_job.join()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()
        if exc_type is None:
            LOGGER.info("Experiment %s finished", self.experiment_name)

    def loop(self) -> None:
        error = False
        while not self.stopped:
            if self.backend_proc.poll() is not None:
                LOGGER.error("Backend crashed")
                error = True
                break
            if self.auditor_proc.poll() is not None:
                LOGGER.error("Auditor crashed")
                error = True
                break
            if self.infra_proc is not None and self.infra_proc.poll() is not None:
                LOGGER.error("Infra crashed")
                error = True
                break
            time.sleep(1)
        LOGGER.info("Sending sigint to background process")
        self.backend_proc.send_signal(signal.SIGINT)
        LOGGER.info("Sending sigint to auditor process")
        self.auditor_proc.send_signal(signal.SIGINT)
        try:
            LOGGER.info("Waiting 60 seconds for background process to respond to SIGINT")
            self.backend_proc.wait(60)
        except subprocess.TimeoutExpired:
            self.backend_proc.kill()
        try:
            LOGGER.info("Waiting 60 seconds for auditor process to terminate")
            self.auditor_proc.wait()
        except subprocess.TimeoutExpired:
            self.auditor_proc.kill()
        if self.infra_proc is not None:
            LOGGER.info("Killing the infra proc")
            self.infra_proc.kill()
        if not self.backend_stderr_file.closed:
            self.backend_stderr_file.close()
        if not self.backend_stdout_file.closed:
            self.backend_stdout_file.close()
        if not self.auditor_stdout_file.closed:
            self.auditor_stdout_file.close()
        if not self.auditor_stderr_file.closed:
            self.auditor_stderr_file.close()
        if not self.infra_stderr_file.closed:
            self.infra_stderr_file.close()
        if not self.infra_stdout_file.closed:
            self.infra_stdout_file.close()
        self.sock_folder.cleanup()
        if error:
            # need to terminate the current process if error, since this is in the background loop
            os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
