import logging
import os
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Dict, Iterable, Mapping, Optional
from unittest.mock import Mock

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
from common.constants import CURRENCY_PRECISIONS, SECP256K1_GROUP, Blockchain, Currency
from common.utils.datetime import get_current_datetime
from common.utils.server_exception_interceptor import ServerExceptionInterceptor
from common.utils.zk import NIZK
from common.utils.zk.currency_conversion import verify_currency_conversion_commitment
from dotenv import load_dotenv
from eth_account.account import Account as ETHAccount
from eth_typing.encoding import HexStr
from eth_typing.evm import ChecksumAddress, HexAddress
from hexbytes.main import HexBytes
from petlib.ec import EcPt
from protobufs.audit_pb2 import CurrencyConversion
from web3.middleware.geth_poa import geth_poa_middleware
from web3.providers.rpc import HTTPProvider
from web3.types import TxReceipt

from auditor.audit_processor import AuditProcessor
from auditor.config import AuditorConfig, WebauthnConfig
from auditor.exceptions import AuditProcessorFailedException
from auditor.sql.audit import Audit
from auditor.sql.block import Block
from auditor.utils.blockchain_client.eth import ETHClient

mock_generated_uuids = []

ETH_DOTENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "infra", "output", "eth.env")
ETH_CONTRACTS_DOTENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "infra", "output", "eth_contracts.env")

LOGGER = logging.getLogger(__name__)

load_dotenv(ETH_DOTENV_PATH)
load_dotenv(ETH_CONTRACTS_DOTENV_PATH)


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


def generate_eth_fixture(eth_client: ETHClient, private_key: HexBytes) -> ETHFixture:
    w3 = eth_client._w3  # pylint: disable=protected-access
    account = ETHAccount.from_key(private_key)  # pylint: disable=no-value-for-parameter
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
    for _ in range(5):
        try:
            tx = proxy.getrawtransaction(transaction_id, verbose=True)
        except IndexError:
            time.sleep(1)
            continue
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


def generate_btc_fixture(private_key: HexBytes) -> BTCFixture:
    proxy = Proxy(service_url=BTC_SERVICE_URL)
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


def generate_mock_config(tempdir_name: str) -> AuditorConfig:
    audit_folder = os.path.join(tempdir_name, "audits")
    os.makedirs(audit_folder)
    return AuditorConfig(
        sqlalchemy_config=SQLAlchemyConfig(
            uri=f"sqlite:///{tempdir_name}/test.db",
            echo=False,
            pool_size=10,
            max_overflow=1,
        ),
        webauthn_config=WebauthnConfig(
            rp_name="localhost",
            rp_id="localhost",
            origin="https://localhost:3000",
        ),
        grpc_server_config=GRPCServerConfig(
            grpc_config=GRPCConfig(
                host=f"unix://{tempdir_name}/grpc.sock",
                max_workers=10,
            ),
            interceptors=(ServerExceptionInterceptor(),),
        ),
        w3_config=W3Config(
            provider=HTTPProvider("http://localhost:8545"),
            middlewares=(geth_poa_middleware,),
            chain_id=58,
            start_block_number=1,  # this is overridden by the tests
            stablecoin_to_erc20_contract_address={
                Currency.GUSD: os.environ["GUSD_CONTRACT_ADDRESS"],
            },
            max_workers=10,
        ),
        ipfs_config=IPFSConfig(
            ipfs_host_uri="/ip4/127.0.0.1/tcp/5001",
            chunk_size=1024,
        ),
        btc_proxy_config=BTCProxyConfig(
            btc_node_type="regtest",
            btc_service_url=BTC_SERVICE_URL,
            start_block_number=1,
            max_workers=10,
        ),
        audit_folder=audit_folder,
        audit_smart_contract_address="",  # for the test cases, we don't listen to the actual blockchain
        acceptable_exchange_rate_epsilon=Decimal("10000"),  # effectively disabling exchange rate validation
    )


def mock_process_new_block(
    self: AuditProcessor,
    bitcoin_block: int,
    ethereum_block: int,
) -> None:
    with self._sessionmaker() as session:  # pylint: disable=protected-access
        session.add(
            Block(
                blockchain=Blockchain.BTC,
                block_number=bitcoin_block,
                block_hash=HexBytes(str(bitcoin_block).encode("utf8")),
                timestamp=get_current_datetime(),
                processed=True,
            )
        )
        session.add(
            Block(
                blockchain=Blockchain.ETH,
                block_number=ethereum_block,
                block_hash=HexBytes(str(ethereum_block).encode("utf8")),
                processed=True,
                timestamp=get_current_datetime(),
            )
        )
        session.commit()
    assert (
        self._blockchain_client.get_latest_processed_block_number(Blockchain.BTC)  # pylint: disable=protected-access
        == bitcoin_block
    )
    assert (
        self._blockchain_client.get_latest_processed_block_number(Blockchain.ETH)  # pylint: disable=protected-access
        == ethereum_block
    )


def mock_convert_to_base_currency_commitment(
    self: AuditProcessor,  # pylint: disable=unused-argument
    audit: Audit,
    currency_conversions: Iterable[CurrencyConversion],
    currency_to_commitment: Mapping[Currency, EcPt],  # pylint: disable=unused-argument
) -> EcPt:
    total = EcPt(SECP256K1_GROUP)
    currency_to_currency_conversion: Dict[Currency, CurrencyConversion] = {}
    currency_to_exchange_rate: Dict[Currency, Fraction] = {}
    for exchange_rate in audit.exchange_rates.exchangeRates:
        currency = Currency[exchange_rate.currency]
        assert currency not in currency_to_exchange_rate
        currency_to_exchange_rate[currency] = Fraction(exchange_rate.rate)
    for currency_conversion in currency_conversions:
        if audit.version_number != currency_conversion.auditVersion:
            raise AuditProcessorFailedException("audit version mismatch")
        currency_to_currency_conversion[Currency[currency_conversion.fromCurrency]] = currency_conversion
    for currency in Currency:
        currency_conversion = currency_to_currency_conversion[currency]
        from_currency_commitment = EcPt.from_binary(currency_conversion.fromCurrencyCommitment, SECP256K1_GROUP)
        to_currency = Currency[currency_conversion.toCurrency]
        if to_currency != audit.base_currency:
            raise AuditProcessorFailedException(
                f"To currency {currency_conversion.toCurrency} for from currency of {currency} != "
                f"audit base currency currency {audit.base_currency}"
            )
        to_currency_commitment = EcPt.from_binary(currency_conversion.toCurrencyCommitment, SECP256K1_GROUP)
        rate = currency_to_exchange_rate[currency]
        nizk = NIZK.deserialize(currency_conversion.nizk)
        verify_currency_conversion_commitment(
            from_currency_commitment, to_currency_commitment, currency, to_currency, rate, nizk
        )
        total += to_currency_commitment
    return total


def mock_return_true(*args: object, **kwargs: object) -> bool:  # pylint: disable=unused-argument
    return True


def mock_return_none(*args: object, **kwargs: object) -> None:  # pylint: disable=unused-argument
    return None


def mock_return_zero(*args: object, **kwargs: object) -> Decimal:  # pylint: disable=unused-argument
    return Decimal(0)
