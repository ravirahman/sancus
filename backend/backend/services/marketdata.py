import logging
import uuid
from typing import List

import grpc
import sqlalchemy.orm
from common.constants import CURRENCY_DECIMALS, Blockchain, Currency
from common.utils.datetime import datetime_to_protobuf
from protobufs.institution.marketdata_pb2 import (
    CurrencyResponse,
    ExchangeRate,
    GetLatestProcessedBlockNumberRequest,
    GetLatestProcessedBlockNumberResponse,
    GetMarketExchangeRateRequest,
    GetMarketExchangeRateResponse,
    GetMarketQuoteRequest,
    GetMarketQuoteResponse,
    ListCurrencyRequest,
    ListCurrencyResponse,
)
from protobufs.institution.marketdata_pb2_grpc import (
    MarketdataServicer,
    add_MarketdataServicer_to_server,
)

from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.jwt_client import AuthenticatedServicer, JWTClient, authenticated
from backend.utils.marketdata_client import MarketdataClient

LOGGER = logging.getLogger(__name__)


class MarketdataService(MarketdataServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        marketdata_client: MarketdataClient,
        blockchain_client: BlockchainClient,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._jwt_client = jwt_client
        self._marketdata_client = marketdata_client
        self._blockchain_client = blockchain_client
        add_MarketdataServicer_to_server(self, server)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    def GetLatestProcessedBlockNumber(
        self, request: GetLatestProcessedBlockNumberRequest, context: grpc.ServicerContext
    ) -> GetLatestProcessedBlockNumberResponse:
        blockchain = Blockchain[request.blockchain]
        block_number = self._blockchain_client.get_latest_processed_block_number(blockchain)
        if block_number is None:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "No blocks processed")
            raise ValueError("No blocks processed")
        return GetLatestProcessedBlockNumberResponse(blockNumber=block_number)

    def ListCurrencies(self, request: ListCurrencyRequest, context: grpc.ServicerContext) -> ListCurrencyResponse:
        # for now, no need to implement the next logic -- there's only three tokens!
        currency_responses: List[CurrencyResponse] = []
        for currency in Currency:
            currency_responses.append(
                CurrencyResponse(
                    symbol=currency.name,
                    name=currency.value,
                    decimals=CURRENCY_DECIMALS[currency],
                )
            )
        return ListCurrencyResponse(response=currency_responses)

    def GetMarketQuote(self, request: GetMarketQuoteRequest, context: grpc.ServicerContext) -> GetMarketQuoteResponse:
        from_currency = Currency[request.fromCurrency]
        to_currency = Currency[request.toCurrency]
        price, timestamp = self._marketdata_client.get_latest_quote(
            sell_currency=from_currency, buy_currency=to_currency
        )
        return GetMarketQuoteResponse(rate=str(price.normalize()), timestamp=datetime_to_protobuf(timestamp))

    @authenticated
    def GetMarketExchangeRate(
        self,
        request: GetMarketExchangeRateRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> GetMarketExchangeRateResponse:
        from_currency = Currency[request.fromCurrency]
        to_currency = Currency[request.toCurrency]
        price_with_spread, timestamp = self._marketdata_client.get_quote_with_spread(
            sell_currency=from_currency, buy_currency=to_currency
        )
        exchange_rate = ExchangeRate(
            rate=str(price_with_spread.normalize()),
            fromCurrency=from_currency.name,
            toCurrency=to_currency.name,
        )
        rate_jwt = self._jwt_client.issue_rate_jwt(user_uuid, exchange_rate, timestamp)
        return GetMarketExchangeRateResponse(exchangeRateJWT=rate_jwt)
