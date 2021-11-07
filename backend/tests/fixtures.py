import contextlib
import logging
import os
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Tuple
from unittest.mock import Mock

import web3
from bitcoin.core import COIN, CTransaction
from bitcoin.rpc import Proxy
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from common.config import (
    BTCProxyConfig,
    GRPCConfig,
    GRPCServerConfig,
    IPFSConfig,
    SQLAlchemyConfig,
    W3Config,
)
from common.constants import CURRENCY_PRECISIONS, Currency
from common.utils.datetime import get_current_datetime
from common.utils.server_exception_interceptor import ServerExceptionInterceptor
from dotenv import load_dotenv
from eth_account.account import Account as ETHAccount
from eth_typing.encoding import HexStr
from eth_typing.evm import ChecksumAddress, HexAddress
from hexbytes.main import HexBytes
from web3.middleware.geth_poa import geth_poa_middleware
from web3.providers.rpc import HTTPProvider
from web3.types import TxReceipt

from auditgen.config import AuditGenConfig
from backend.config import (
    BackendConfig,
    BTCConfig,
    ETHConfig,
    JWTConfig,
    WebauthnConfig,
)
from backend.utils.blockchain_client.eth import ETHClient
from backend.utils.jwt_client import JWTClient
from backend.utils.marketdata_client import MarketdataClient

mock_generated_uuids = []

ETH_DOTENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "infra", "output", "eth.env")
ERC20_DOTENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "infra", "output", "eth_contracts.env")

LOGGER = logging.getLogger(__name__)

load_dotenv(ETH_DOTENV_PATH)
load_dotenv(ERC20_DOTENV_PATH)


def _save_and_return_mock_uuid() -> uuid.UUID:
    mock_uuid = uuid.uuid4()
    mock_generated_uuids.append(mock_uuid)
    return mock_uuid


mock_generate_uuid4 = Mock(side_effect=_save_and_return_mock_uuid)

MOCK_USER_UUID = uuid.UUID("8b29ffd9-a758-46cb-a6bb-1b4423e65fb9")
MOCK_ACCOUNT_UUID = uuid.UUID("091645d1-1ec7-4b34-91db-a311734aace6")
_MOCK_PRIVATE_KEY_FILENAME = os.path.join(os.path.dirname(__file__), "..", "..", "sancus.key")
_MOCK_CERTIFICATE_FILENAME = os.path.join(os.path.dirname(__file__), "..", "..", "sancus.crt")
_MOCK_PEM_FILENAME = os.path.join(os.path.dirname(__file__), "..", "..", "sancus.pem")

MOCK_JWT_CONFIG = JWTConfig(
    private_key_file=_MOCK_PRIVATE_KEY_FILENAME,
    public_key_file=_MOCK_PEM_FILENAME,
    auth_duration=timedelta(days=1),
    rate_duration=timedelta(days=1),
    issuer="localhost",
    algorithm="RS256",
)

BTCUSD_RATE = Decimal(60000)
ETHUSD_RATE = Decimal(2200)
ETHBTC_RATE = Decimal("0.03619")

W3_PROVIDER = HTTPProvider("http://localhost:8545")
W3_MIDDLEWARES = (geth_poa_middleware,)
BTC_SERVICE_URL = "http://bitcoin:password@localhost:18444"


def get_latest_btc_block_number() -> int:
    with contextlib.closing(Proxy(BTC_SERVICE_URL, timeout=60)) as proxy:
        block_count = proxy.getblockcount()
        assert isinstance(block_count, int)
        return block_count


def get_latest_eth_block_number() -> int:
    w3 = web3.Web3(provider=W3_PROVIDER, middlewares=W3_MIDDLEWARES)
    block_number = int(w3.eth.block_number)
    return block_number


def mock_get_quote(
    self: MarketdataClient,  # pylint: disable=unused-argument
    symbol: str,
) -> Tuple[Decimal, datetime]:
    if symbol == "btcusd":
        return BTCUSD_RATE, get_current_datetime()
    if symbol == "ethusd":
        return ETHUSD_RATE, get_current_datetime()
    if symbol == "ethbtc":
        return ETHBTC_RATE, get_current_datetime()
    raise ValueError(f"invalid symbol: {symbol}")


MOCK_EXCHANGE_RATE_SPREAD = Decimal("1.05")
# doing a global patch instead of a monkeypatch so it will be swapped in setup methods
MarketdataClient._get_quote = mock_get_quote  # type: ignore[assignment] # pylint: disable=protected-access


def generate_w3_config(start_block_number: int) -> W3Config:
    return W3Config(
        provider=W3_PROVIDER,
        middlewares=W3_MIDDLEWARES,
        start_block_number=start_block_number,
        chain_id=58,
        stablecoin_to_erc20_contract_address={
            Currency.GUSD: os.environ["GUSD_CONTRACT_ADDRESS"],
        },
        max_workers=1,
    )


MAIN_ETH_ACCOUNT = ChecksumAddress(HexAddress(HexStr(os.environ["ETH_MAIN_ADDRESS"])))
ETH1_AMOUNT = Decimal("0.1")
ETH2_AMOUNT = Decimal("0.2")
GUSD1_AMOUNT = Decimal("10")
GUSD2_AMOUNT = Decimal("15")


@dataclass
class ETHFixture:
    private_key: HexBytes
    address: str
    eth1_tx_receipt: TxReceipt
    eth2_tx_receipt: TxReceipt
    gusd1_tx_receipt: TxReceipt
    gusd2_tx_receipt: TxReceipt


def generate_eth_fixture(eth_client: ETHClient) -> ETHFixture:
    w3 = eth_client._w3  # pylint: disable=protected-access
    account = ETHAccount.create()  # pylint: disable=no-value-for-parameter
    private_key = account.key
    address = account.address
    gusd_contract = eth_client._stablecoin_to_contract[Currency.GUSD]  # pylint: disable=protected-access

    eth1_hash = w3.eth.send_transaction(
        {
            "from": MAIN_ETH_ACCOUNT,
            "to": address,
            "value": eth_client.eth_to_wei(ETH1_AMOUNT),
        }
    )

    gusd1_hash = gusd_contract.functions.transfer(
        address,
        int(GUSD1_AMOUNT * CURRENCY_PRECISIONS[Currency.GUSD]),
    ).transact({"from": MAIN_ETH_ACCOUNT})

    gusd1_tx_receipt = w3.eth.waitForTransactionReceipt(gusd1_hash, timeout=20)
    eth1_tx_receipt = w3.eth.waitForTransactionReceipt(eth1_hash, timeout=20)
    eth2_hash = w3.eth.send_transaction(
        {
            "from": MAIN_ETH_ACCOUNT,
            "to": address,
            "value": eth_client.eth_to_wei(ETH2_AMOUNT),
        }
    )

    gusd2_hash = gusd_contract.functions.transfer(
        address,
        int(GUSD2_AMOUNT * CURRENCY_PRECISIONS[Currency.GUSD]),
    ).transact({"from": MAIN_ETH_ACCOUNT})
    gusd2_tx_receipt = w3.eth.waitForTransactionReceipt(gusd2_hash, timeout=20)
    eth2_tx_receipt = w3.eth.waitForTransactionReceipt(eth2_hash, timeout=20)
    return ETHFixture(
        private_key=private_key,
        address=address,
        eth1_tx_receipt=eth1_tx_receipt,
        eth2_tx_receipt=eth2_tx_receipt,
        gusd1_tx_receipt=gusd1_tx_receipt,
        gusd2_tx_receipt=gusd2_tx_receipt,
    )


class EthFixturesContainer:
    def __init__(self, eth_client: ETHClient, size: int):
        self.index = 0
        with ThreadPoolExecutor(max_workers=size) as executor:
            futures = [executor.submit(generate_eth_fixture, eth_client) for _ in range(size)]
            self.fixtures = [future.result() for future in futures]

    def __call__(self) -> ETHFixture:
        fixture = self.fixtures[self.index]
        self.index += 1
        return fixture


BTC_AMOUNT_1 = Decimal("0.1")
BTC_AMOUNT_2 = Decimal("0.2")

BTC_SERVICE_URL = "http://bitcoin:password@localhost:18444"


@dataclass(frozen=True)
class TxInfo:
    blockhash: HexBytes
    blockheight: int
    tx: CTransaction


def wait_for_eth_block(eth_client: ETHClient, block_number: int, timeout_seconds: int = 20) -> None:
    for i in range(timeout_seconds):
        if eth_client.get_latest_block_number_from_chain() >= block_number:
            break
        if i < timeout_seconds - 1:
            time.sleep(1)
            continue
        raise RuntimeError("Timeout")


def wait_for_bitcoin_tx(proxy: Proxy, transaction_id: HexBytes) -> TxInfo:
    for _ in range(20):
        tx = proxy.getrawtransaction(transaction_id, verbose=True)
        if tx["blockhash"] is None:
            time.sleep(1)
            continue
        block_header = proxy.getblockheader(tx["blockhash"], verbose=True)
        return TxInfo(blockhash=HexBytes(tx["blockhash"]), blockheight=block_header["height"], tx=tx["tx"])
    raise RuntimeError("Unable to get-chain confirmation")


@dataclass(frozen=True)
class BTCFixture:
    private_key: HexBytes
    address: str
    tx_1: TxInfo
    tx_2: TxInfo


def generate_btc_fixture() -> BTCFixture:
    with contextlib.closing(Proxy(service_url=BTC_SERVICE_URL)) as proxy:
        private_key = HexBytes(secrets.randbits(256).to_bytes(32, "big", signed=False))
        public_key = CBitcoinSecret.from_secret_bytes(private_key).pub
        address = P2PKHBitcoinAddress.from_pubkey(public_key)
        txid1 = proxy.sendtoaddress(str(address), int(BTC_AMOUNT_1 * COIN))
        tx1: Optional[TxInfo] = None
        for _ in range(5):
            tx1 = wait_for_bitcoin_tx(proxy, txid1)
            break
        if tx1 is None:
            raise RuntimeError("Unable to get chain confirmation")
        txid2 = proxy.sendtoaddress(str(address), int(BTC_AMOUNT_2 * COIN))
        tx2: Optional[TxInfo] = None
        for _ in range(5):
            tx2 = wait_for_bitcoin_tx(proxy, txid2)
            break
        if tx2 is None:
            raise RuntimeError("Unable to get-chain confirmation")
        return BTCFixture(
            private_key=private_key,
            address=str(address),
            tx_1=tx1,
            tx_2=tx2,
        )


class BtcFixturesContainer:
    def __init__(self, size: int):
        self.index = 0

        with ThreadPoolExecutor(max_workers=size) as executor:
            futures = [executor.submit(generate_btc_fixture) for _ in range(size)]
            self.fixtures = [future.result() for future in futures]

    def __call__(self) -> BTCFixture:
        fixture = self.fixtures[self.index]
        self.index += 1
        return fixture


def generate_grpc_config(tempdir_name: str) -> GRPCConfig:
    return GRPCConfig(
        host=f"unix://{tempdir_name}/grpc.sock",
        max_workers=1,  # all requests in tests are one-at-a-time
    )


def generate_mock_auditgen_config(tempdir_name: str, eth_start_block_number: int) -> AuditGenConfig:
    return AuditGenConfig(
        audit_smart_contract_address=os.environ["AUDIT_PUBLISHER_CONTRACT_ADDRESS"],
        audit_publisher_address=os.environ["ETH_CONTRACTS_OWNER"],
        jwt_config=MOCK_JWT_CONFIG,
        grpc_config=generate_grpc_config(tempdir_name),
        ipfs_config=IPFSConfig(
            ipfs_host_uri="/ip4/127.0.0.1/tcp/5001",
            chunk_size=1024,
        ),
        w3_config=generate_w3_config(eth_start_block_number),
    )


def generate_mock_backend_config(
    tempdir_name: str, eth_start_block_number: int, btc_start_block_number: int
) -> BackendConfig:
    return BackendConfig(
        sqlalchemy_config=SQLAlchemyConfig(
            uri=f"sqlite:///{tempdir_name}/test.db",
            echo=False,
            pool_size=1,
            max_overflow=1,
        ),
        grpc_server_config=GRPCServerConfig(
            grpc_config=generate_grpc_config(tempdir_name),
            interceptors=(ServerExceptionInterceptor(),),
        ),
        webauthn_config=WebauthnConfig(
            rp_name="localhost",
            rp_id="localhost",
            timeout=timedelta(seconds=0),  # ignored in tests
            origin="https://localhost:3000",
            challenge_duration=timedelta(hours=1),
        ),
        jwt_config=MOCK_JWT_CONFIG,
        eth_config=ETHConfig(
            w3_config=generate_w3_config(eth_start_block_number),
            num_confirmations=2,
            rebroadcast_interval=timedelta(days=1000),  # effectively disable rebroadcasting
            transaction_timeout=timedelta(seconds=0),
            default_address=os.environ["ETH_MAIN_ADDRESS"],
        ),
        btc_config=BTCConfig(
            proxy_config=BTCProxyConfig(
                btc_node_type="regtest",
                btc_service_url=BTC_SERVICE_URL,
                start_block_number=btc_start_block_number,
                max_workers=10,
            ),
            num_confirmations=2,
            rebroadcast_interval=timedelta(days=10000),  # effectively disable rebroadcasting
            transaction_timeout=timedelta(seconds=0),
        ),
        exchange_rate_spread=MOCK_EXCHANGE_RATE_SPREAD,
        account_anonymity_set_size=10,
        deposit_key_decoy_set_size=10,
    )


def get_mock_jwt(user_uuid: uuid.UUID) -> str:
    jwt_client = JWTClient(MOCK_JWT_CONFIG)
    mock_auth_jwt = jwt_client.issue_auth_jwt(user_uuid)
    return mock_auth_jwt
