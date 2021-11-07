import json
import logging
import os
import queue
import signal
import socket
import threading
from datetime import timedelta
from types import TracebackType
from typing import Optional, Type

import requests
import sqlalchemy.orm
from common.constants import ADMIN_UUID, CURRENCY_TO_BLOCKCHAIN, Blockchain, Currency
from common.utils.grpc_server import GRPCServer
from common.utils.spinner import Spinner
from common.utils.sqlalchemy_engine import make_sqlalchemy_engine
from sqlalchemy.exc import OperationalError

from backend.config import BackendConfig
from backend.services.account import AccountService
from backend.services.audit_gen.account import AuditGenAccountService
from backend.services.audit_gen.account_delta_group import (
    AuditGenAccountDeltaGroupService,
)
from backend.services.audit_gen.audit import AuditGenService
from backend.services.audit_gen.key import AuditGenKeyService
from backend.services.audit_gen.key_account import AuditGenKeyAccountService
from backend.services.audit_gen.key_account_liability import (
    AuditGenKeyAccountLiabilityService,
)
from backend.services.audit_gen.key_currency_asset import (
    AuditGenKeyCurrencyAssetService,
)
from backend.services.audit_gen.user_cumulative_liability import (
    AuditGenUserCumulativeLiabilityService,
)
from backend.services.audit_gen.user_key import AuditGenUserKeyService
from backend.services.auth import AuthService
from backend.services.deposit import DepositService
from backend.services.exchange import ExchangeService
from backend.services.marketdata import MarketdataService
from backend.services.withdrawal import WithdrawalService
from backend.sql.base import Base
from backend.sql.key import Key
from backend.sql.key_currency_account import KeyCurrencyAccount
from backend.utils.blockchain_client.btc import BTCClient
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.blockchain_client.eth import ETHClient
from backend.utils.jwt_client import JWTClient
from backend.utils.key_client import KeyClient
from backend.utils.marketdata_client import MarketdataClient
from backend.utils.webauthn_client import WebauthnClient

LOGGER = logging.getLogger(__name__)

SERVICE_NAMES = [
    "Account",
    "AuditGen",
    "AuditGenAccount",
    "AuditGenAccountDeltaGroup",
    "AuditGenKey",
    "AuditGenKeyAccount",
    "AuditGenKeyAccountLiability",
    "AuditGenKeyCurrencyAsset",
    "AuditGenUserCurrencyLiability",
    "AuditGenUserKey",
    "Auth",
    "Depost",
    "Exchange",
    "Marketdata",
    "Withdrawal",
]


class Backend:
    def __init__(self, config: BackendConfig) -> None:
        self.sqlalchemy_engine = make_sqlalchemy_engine(config.sqlalchemy_config)
        Base.metadata.create_all(self.sqlalchemy_engine)
        self.sessionmaker = sqlalchemy.orm.sessionmaker(bind=self.sqlalchemy_engine)
        self.jwt_client = JWTClient(config.jwt_config)
        self.key_client = KeyClient(self.sessionmaker, config.deposit_key_decoy_set_size)
        self.eth_client = ETHClient(config.eth_config, self.key_client, self.sessionmaker)
        self.btc_client = BTCClient(self.sessionmaker, config.btc_config, self.key_client)
        self.blockchain_client = BlockchainClient(self.eth_client, self.btc_client, self.sessionmaker)
        self.webauthn_client = WebauthnClient(config.webauthn_config)
        self.marketdata_client = MarketdataClient(self.sessionmaker, config.exchange_rate_spread)
        self.config = config
        self.grpc_server = GRPCServer(config.grpc_server_config)
        self.stopped = False

        AuthService(self.sessionmaker, self.jwt_client, self.webauthn_client, self.grpc_server.grpc_server)
        AccountService(self.sessionmaker, self.jwt_client, self.webauthn_client, self.grpc_server.grpc_server)
        DepositService(
            self.sessionmaker,
            self.jwt_client,
            self.key_client,
            self.blockchain_client,
            config.deposit_faucet_amounts,
            self.grpc_server.grpc_server,
        )
        MarketdataService(
            self.sessionmaker,
            self.jwt_client,
            self.marketdata_client,
            self.blockchain_client,
            self.grpc_server.grpc_server,
        )
        ExchangeService(
            self.sessionmaker,
            self.jwt_client,
            self.webauthn_client,
            config.account_anonymity_set_size,
            self.grpc_server.grpc_server,
        )
        WithdrawalService(
            self.sessionmaker,
            self.jwt_client,
            self.webauthn_client,
            config.account_anonymity_set_size,
            self.blockchain_client,
            self.key_client,
            self.grpc_server.grpc_server,
        )
        AuditGenAccountDeltaGroupService(
            self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server, self.blockchain_client
        )
        AuditGenAccountService(self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server)
        AuditGenService(
            self.sessionmaker,
            self.jwt_client,
            self.grpc_server.grpc_server,
            self.blockchain_client,
            self.marketdata_client,
        )
        AuditGenKeyAccountLiabilityService(
            self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server, self.blockchain_client, self.key_client
        )

        AuditGenKeyCurrencyAssetService(
            self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server, self.key_client
        )
        AuditGenKeyAccountService(self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server)
        AuditGenKeyService(self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server)
        AuditGenUserKeyService(self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server)
        AuditGenUserCumulativeLiabilityService(
            self.sessionmaker, self.jwt_client, self.grpc_server.grpc_server, self.blockchain_client, self.key_client
        )

        self.blockchain_processing_threads = [
            threading.Thread(target=self.blockchain_processing_loop, kwargs={"blockchain": blockchain})
            for blockchain in Blockchain
        ]
        self.marketdata_thread = threading.Thread(target=self.marketdata_loop)
        self.faucet_thread = threading.Thread(target=self.faucet_loop)

    def faucet_loop(self) -> None:
        if self.config.deposit_faucet_amounts is None:
            return
        # inject the institution with funds so we can create anonymity sets and process withdrawals
        # without relying on users to deposit funds or use the faucet
        admin_key_uuid = self.key_client.make_new_hot_key()
        spinner = Spinner(timedelta(seconds=10))  # only do a deposit once every n seconds to limit inflation haha
        with self.sessionmaker() as session:
            row_count = (
                session.query(KeyCurrencyAccount)
                .filter(KeyCurrencyAccount.key_uuid == admin_key_uuid, KeyCurrencyAccount.account_uuid == ADMIN_UUID)
                .update(
                    {
                        KeyCurrencyAccount.pending_admin_deposits: KeyCurrencyAccount.pending_admin_deposits + 1,
                    }
                )
            )
            assert row_count == len(Currency), "should have one update per currency"
            key = session.query(Key).filter(Key.key_uuid == admin_key_uuid).one()
            currency_to_address = {currency: key.get_address(CURRENCY_TO_BLOCKCHAIN[currency]) for currency in Currency}
            session.commit()
        while not self.stopped:
            if not spinner():
                continue
            try:
                for currency, amount in self.config.deposit_faucet_amounts.items():
                    LOGGER.info("faucet loop -- infusing the institution with %s %s", currency, amount)
                    address = currency_to_address[currency]
                    self.blockchain_client.deposit(address, currency, amount)
            except (OperationalError, socket.timeout, queue.Empty):
                LOGGER.warning("Error in facuet loop, but retrying on next timestamp", exc_info=True)
            except:  # pylint: disable=bare-except
                LOGGER.error("Fatal exception from the facuet loop", exc_info=True)
                os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)

    def marketdata_loop(self) -> None:
        spinner = Spinner(timedelta(seconds=1))  # update the quotes once per second
        while not self.stopped:
            if not spinner():
                continue
            try:
                self.marketdata_client.update_quotes()
            except (json.JSONDecodeError, requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
                pass
            except:  # pylint: disable=bare-except
                LOGGER.error("Fatal exception from the marketdata loop", exc_info=True)
                os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)

    def blockchain_processing_loop(self, blockchain: Blockchain) -> None:
        spinner = Spinner(timedelta(seconds=1))  # check once per second
        while not self.stopped:
            if not spinner():
                continue
            try:
                latest_processed_block_number = self.blockchain_client.get_latest_processed_block_number(blockchain)
                if latest_processed_block_number is None:
                    block_to_process = self.blockchain_client.get_start_block_number(blockchain)
                else:
                    block_to_process = latest_processed_block_number + 1
                latest_blockchain_block_number = self.blockchain_client.get_latest_block_number_from_chain(blockchain)
                LOGGER.info("latest_blockchain_block_number for %s is %d", blockchain, latest_blockchain_block_number)
                if block_to_process <= latest_blockchain_block_number and (not self.stopped):
                    LOGGER.info("Processing block(%d) on blockchain(%s)", block_to_process, blockchain)
                    self.blockchain_client.process_block(blockchain, block_to_process)
                    LOGGER.info("Finished processing block(%d) on blockchain(%s)", block_to_process, blockchain)
                    block_to_process += 1

            except (OperationalError, socket.timeout, queue.Empty, requests.exceptions.ConnectionError):
                LOGGER.warning(
                    "Error processing block on blockchain(%s), but retrying on next timestamp",
                    blockchain,
                    exc_info=True,
                )
            except:  # pylint: disable=bare-except
                LOGGER.error(
                    "Fatal exception from the blockchain processing loop for blockchain(%s)", blockchain, exc_info=True
                )
                os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
                # skipping OperationalError's since they represent db errors outside our control
                # like failed transactions or locks
                # it's fine, we'll just process this block on the next tick

    def start(self) -> None:
        LOGGER.info("Starting the faucet thread")
        self.faucet_thread.start()
        LOGGER.info("Starting the marketdata thread")
        self.marketdata_thread.start()
        LOGGER.info("Starting the blockchain processing threads")
        for thread in self.blockchain_processing_threads:
            thread.start()
        LOGGER.info("Starting the grpc server")
        self.grpc_server.start()
        LOGGER.info("Backend started")

    def __enter__(self) -> "Backend":
        self.start()
        return self

    def stop(self) -> None:
        self.stopped = True
        LOGGER.info("Stopping the grpc server")
        self.grpc_server.stop()
        LOGGER.info("Joining the blockchian processing threads")
        for thread in self.blockchain_processing_threads:
            thread.join()
        LOGGER.info("Joining the marketdata thread to stop")
        self.marketdata_thread.join()
        LOGGER.info("Joining the faucet thread")
        self.faucet_thread.join()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.stop()
