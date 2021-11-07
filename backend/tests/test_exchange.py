import unittest
from decimal import Decimal

import grpc
import petlib.bn
import petlib.ec
from common.constants import (
    CURRENCY_PRECISIONS,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_GROUP,
    Currency,
)
from common.utils.uuid import bytes_to_uuid
from protobufs.account_pb2 import AccountDeltaGroupChallengeRequest, AccountType
from protobufs.institution.account_pb2 import TransactionStatus, TransactionType
from protobufs.institution.exchange_pb2 import (
    InitiateExchangeRequest,
    ProcessExchangeRequest,
)
from protobufs.institution.exchange_pb2_grpc import ExchangeStub
from protobufs.institution.marketdata_pb2 import GetMarketExchangeRateRequest
from protobufs.institution.marketdata_pb2_grpc import MarketdataStub

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.transaction import Transaction
from backend.utils.jwt_client import JWTClient
from tests.base import BaseBackendTestCase
from tests.fixtures import (
    BTCUSD_RATE,
    MOCK_EXCHANGE_RATE_SPREAD,
    MOCK_JWT_CONFIG,
    MOCK_USER_UUID,
)

BTC_PRICE = BTCUSD_RATE * MOCK_EXCHANGE_RATE_SPREAD
GUSD_STARTING_BAL = Decimal("1000000.00")
EXCHANGE_AMOUNT = Decimal("2.00")


class TestExchange(BaseBackendTestCase):
    exchange_stub: ExchangeStub
    marketdata_stub: MarketdataStub
    jwt_client: JWTClient
    channel: grpc.Channel
    backend: Backend

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.exchange_stub = ExchangeStub(cls.channel)
        cls.marketdata_stub = MarketdataStub(cls.channel)
        cls.jwt_client = JWTClient(MOCK_JWT_CONFIG)

    def setUp(self) -> None:
        super().setUp()
        with self.backend.sessionmaker() as session:
            gusd_account = Account(
                account_type=AccountType.DEPOSIT_ACCOUNT,
                user_uuid=MOCK_USER_UUID,
                currency=Currency.GUSD,
                available_amount=GUSD_STARTING_BAL,
            )
            session.add(gusd_account)
            btc_account = Account(
                account_type=AccountType.DEPOSIT_ACCOUNT,
                user_uuid=MOCK_USER_UUID,
                currency=Currency.BTC,
            )
            session.add(btc_account)
            session.commit()
            self.gusd_account_uuid = gusd_account.uuid
            self.btc_account_uuid = btc_account.uuid

    def test_initiate_exchange(self) -> None:
        marketdata_request = GetMarketExchangeRateRequest(
            fromCurrency=Currency.GUSD.name,
            toCurrency=Currency.BTC.name,
        )
        marketdata_response = self.marketdata_stub.GetMarketExchangeRate(marketdata_request)
        request = InitiateExchangeRequest(
            exchangeRateJWT=marketdata_response.exchangeRateJWT,
            amount=str(EXCHANGE_AMOUNT.normalize()),
            fromAccountId=self.gusd_account_uuid.bytes,
            toAccountId=self.btc_account_uuid.bytes,
        )
        response = self.exchange_stub.InitiateExchange(request)
        challenge_request_any_pb = response.challengeRequest.request
        exchange_challenge_request = AccountDeltaGroupChallengeRequest()
        self.assertTrue(challenge_request_any_pb.Unpack(exchange_challenge_request))
        public_commitments = exchange_challenge_request.commitments
        for revealed_commitment, public_commitment in zip(response.revealedCommitments, public_commitments):
            self.assertEqual(public_commitment.accountId, revealed_commitment.accountId)
            account_id = bytes_to_uuid(public_commitment.accountId)
            amount_bn = petlib.bn.Bn.from_decimal(revealed_commitment.commitment.x)
            self.assertEqual(
                petlib.ec.EcPt.from_binary(public_commitment.commitment, SECP256K1_GROUP),
                petlib.bn.Bn.from_decimal(revealed_commitment.commitment.x) * SECP256K1_GENERATOR
                + petlib.bn.Bn.from_decimal(revealed_commitment.commitment.r) * SECP256K1_ALTERNATIVE_GENERATOR,
            )
            expected_amount = Decimal(0)
            if account_id == self.gusd_account_uuid:
                expected_amount = -BTC_PRICE * Decimal(CURRENCY_PRECISIONS[Currency.GUSD])
            if account_id == self.btc_account_uuid:
                expected_amount = Decimal(CURRENCY_PRECISIONS[Currency.BTC])
            expected_amount *= EXCHANGE_AMOUNT
            expected_amount_bn = petlib.bn.Bn.from_decimal(str(int(expected_amount)))
            self.assertEqual(amount_bn, expected_amount_bn)

    def test_process_exchange(self) -> None:
        marketdata_request = GetMarketExchangeRateRequest(
            fromCurrency=Currency.GUSD.name,
            toCurrency=Currency.BTC.name,
        )
        marketdata_response = self.marketdata_stub.GetMarketExchangeRate(marketdata_request)
        initiate_request = InitiateExchangeRequest(
            exchangeRateJWT=marketdata_response.exchangeRateJWT,
            amount=str(EXCHANGE_AMOUNT.normalize()),
            fromAccountId=self.gusd_account_uuid.bytes,
            toAccountId=self.btc_account_uuid.bytes,
        )
        initiate_response = self.exchange_stub.InitiateExchange(initiate_request)
        assertion = self.soft_webauthn.request_assertion(
            initiate_response.challengeRequest, initiate_response.credentialRequest
        )
        process_request = ProcessExchangeRequest(id=initiate_response.id, assertion=assertion)
        self.exchange_stub.ProcessExchange(process_request)
        gusd_amount = EXCHANGE_AMOUNT * BTC_PRICE

        with self.backend.sessionmaker() as session:
            gusd_account = (
                session.query(Account)
                .filter(
                    Account.account_type == AccountType.DEPOSIT_ACCOUNT,
                    Account.user_uuid == MOCK_USER_UUID,
                    Account.currency == Currency.GUSD,
                )
                .one()
            )
            self.assertEqual(gusd_account.available_amount, GUSD_STARTING_BAL - gusd_amount)

            btc_account = (
                session.query(Account)
                .filter(
                    Account.account_type == AccountType.DEPOSIT_ACCOUNT,
                    Account.user_uuid == MOCK_USER_UUID,
                    Account.currency == Currency.BTC,
                )
                .one()
            )
            self.assertEqual(btc_account.available_amount, EXCHANGE_AMOUNT)

            gusd_transaction = (
                session.query(Transaction)
                .filter(
                    Transaction.account_uuid == gusd_account.uuid,
                    Transaction.transaction_type == TransactionType.EXCHANGE,
                    Transaction.status == TransactionStatus.COMPLETED,
                )
                .one()
            )
            self.assertEqual(gusd_transaction.amount, -gusd_amount)

            btc_transaction = (
                session.query(Transaction)
                .filter(
                    Transaction.account_uuid == btc_account.uuid,
                    Transaction.transaction_type == TransactionType.EXCHANGE,
                    Transaction.status == TransactionStatus.COMPLETED,
                )
                .one()
            )
            self.assertEqual(btc_transaction.amount, EXCHANGE_AMOUNT)


if __name__ == "__main__":
    unittest.main()
