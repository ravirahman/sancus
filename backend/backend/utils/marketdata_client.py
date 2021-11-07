import logging
from datetime import datetime
from decimal import Decimal
from typing import Tuple

import pytz
import requests
from common.constants import Currency
from common.utils.datetime import get_current_datetime
from sqlalchemy.orm import sessionmaker

from backend.sql.exchange_rate import ExchangeRate

GEMINI_BASE_URL = "https://api.gemini.com/v1"

LOGGER = logging.getLogger(__name__)


class MarketdataClient:
    symbols = ("btcusd", "ethusd", "ethbtc")

    def __init__(self, session_maker: sessionmaker, spread_factor: Decimal) -> None:
        self._sessionmaker = session_maker
        assert spread_factor >= 1, "spread should be at least 1"
        self._spread_factor = spread_factor
        self.update_quotes()

    def get_latest_quote(self, *, sell_currency: Currency, buy_currency: Currency) -> Tuple[Decimal, datetime]:
        if buy_currency == sell_currency:
            return Decimal("1"), get_current_datetime()
        # returns the cost to buy 1 unit of `buy_currency` in terms of `sell_currency` using the last price
        with self._sessionmaker() as session:
            symbol, is_selling = self._get_symbol_and_is_selling(sell_currency=sell_currency, buy_currency=buy_currency)
            exchange_rate = session.query(ExchangeRate).filter(ExchangeRate.symbol == symbol).one()
            if is_selling:
                return Decimal(1) / exchange_rate.last_price, exchange_rate.timestamp
            return exchange_rate.last_price, exchange_rate.timestamp

    @staticmethod
    def _get_symbol_and_is_selling(*, sell_currency: Currency, buy_currency: Currency) -> Tuple[str, bool]:
        currency_pair = (sell_currency, buy_currency)
        # in a symbol "XXXyyy", you are buying XXX and selling yyy
        # if the buy_currency is XXX and the sell_currency is yyy, then you are buying, so you will need to
        # pay the ask price
        # if the buy_currency is yyy, and the sell currency is XXX, then you are selling, so you will get the bid
        # price
        if Currency.BTC in currency_pair and Currency.GUSD in currency_pair:
            symbol = "btcusd"
            is_selling = sell_currency == Currency.BTC
            return symbol, is_selling
        if Currency.ETH in currency_pair and Currency.GUSD in currency_pair:
            symbol = "ethusd"
            is_selling = sell_currency == Currency.ETH
            return symbol, is_selling
        if Currency.BTC in currency_pair and Currency.ETH in currency_pair:
            symbol = "ethbtc"
            is_selling = sell_currency == Currency.ETH
            return symbol, is_selling
        raise ValueError("Invalid currency pair")

    @staticmethod
    def _get_quote(symbol: str) -> Tuple[Decimal, datetime]:
        resp = requests.get(GEMINI_BASE_URL + f"/trades/{symbol}", params={"limit_trades": 1})
        resp.raise_for_status()
        trades_info = resp.json()
        last_price = Decimal(trades_info[0]["price"])
        timestamp = datetime.fromtimestamp(trades_info[0]["timestampms"] / 1000, pytz.UTC)
        LOGGER.info("Quote for symobl %s at timestamp %s has price of %s", symbol, timestamp, last_price)
        return last_price, timestamp

    def update_quotes(self) -> None:
        for symbol in self.symbols:
            last_price, timestamp = self._get_quote(symbol)
            with self._sessionmaker() as session:
                session.merge(
                    ExchangeRate(
                        symbol=symbol,
                        last_price=last_price,
                        timestamp=timestamp,
                    )
                )
                session.commit()

    def get_quote_with_spread(self, *, sell_currency: Currency, buy_currency: Currency) -> Tuple[Decimal, datetime]:
        if sell_currency == buy_currency:
            return Decimal("1"), get_current_datetime()
        symbol, is_selling = self._get_symbol_and_is_selling(sell_currency=sell_currency, buy_currency=buy_currency)
        with self._sessionmaker() as session:
            exchange_rate = session.query(ExchangeRate).filter(ExchangeRate.symbol == symbol).one()
            if is_selling:
                price = Decimal(1) / exchange_rate.last_price
            else:
                price = exchange_rate.last_price
            price_with_spread = self._spread_factor * price
            return price_with_spread, exchange_rate.timestamp
