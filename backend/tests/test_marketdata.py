import unittest

import grpc
from common.constants import CURRENCY_DECIMALS, Currency
from protobufs.institution.marketdata_pb2 import (
    ExchangeRate,
    GetMarketExchangeRateRequest,
    GetMarketQuoteRequest,
    ListCurrencyRequest,
)
from protobufs.institution.marketdata_pb2_grpc import MarketdataStub

from backend.utils.jwt_client import JWTClient
from tests.base import BaseBackendTestCase
from tests.fixtures import (
    BTCUSD_RATE,
    MOCK_EXCHANGE_RATE_SPREAD,
    MOCK_JWT_CONFIG,
    MOCK_USER_UUID,
)


class TestMarketdata(BaseBackendTestCase):
    marketdata_stub: MarketdataStub
    jwt_client: JWTClient
    channel: grpc.Channel

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.marketdata_stub = MarketdataStub(cls.channel)
        cls.jwt_client = JWTClient(MOCK_JWT_CONFIG)

    def test_get_market_exchange_rate(self) -> None:
        request = GetMarketQuoteRequest(fromCurrency=Currency.GUSD.name, toCurrency=Currency.BTC.name)
        response = self.marketdata_stub.GetMarketQuote(request)
        self.assertEqual(
            response.rate,
            str(BTCUSD_RATE.normalize()),
        )

    def test_get_market_quote(self) -> None:
        expected_rate = str((BTCUSD_RATE * MOCK_EXCHANGE_RATE_SPREAD).normalize())
        request = GetMarketExchangeRateRequest(fromCurrency=Currency.GUSD.name, toCurrency=Currency.BTC.name)
        response = self.marketdata_stub.GetMarketExchangeRate(request)
        exchange_rate, ignored_exchange_rate_expiration = self.jwt_client.decode_rate_jwt(
            MOCK_USER_UUID, response.exchangeRateJWT
        )
        self.assertEqual(
            exchange_rate,
            ExchangeRate(fromCurrency=Currency.GUSD.name, toCurrency=Currency.BTC.name, rate=expected_rate),
        )

    def test_list_currencies(self) -> None:
        counter = 0
        request = ListCurrencyRequest()
        while True:
            response = self.marketdata_stub.ListCurrencies(request)
            for res in response.response:
                counter += 1
                currency = Currency[res.symbol]
                self.assertEqual(res.name, currency.value)
                self.assertEqual(res.decimals, CURRENCY_DECIMALS[currency])
            if response.nextToken == "":
                break
            request = ListCurrencyRequest(nextToken=response.nextToken)
        self.assertEqual(counter, len(Currency))


if __name__ == "__main__":
    unittest.main()
