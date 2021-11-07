from datetime import datetime, timedelta
from decimal import Decimal
from typing import Tuple

import requests
from common.constants import Currency

GEMINI_BASE_URL = "https://api.gemini.com/v1"
LIMIT_TRADE_HISTORY = 50


class MarketdataClient:
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

    def get_quote_at_timestamp(self, from_currency: Currency, to_currency: Currency, timestamp: datetime) -> Decimal:
        """
        Sends a GET request to Gemini API for historical trading data.
        Attempts to get data at timestamp, but steps back one hour at a time if no data is retrieved.
        """
        if from_currency == to_currency:
            return Decimal("1")
        symbol, is_selling = self._get_symbol_and_is_selling(sell_currency=from_currency, buy_currency=to_currency)

        time_back = timedelta(0)
        max_tries = 24  # in case a bad timestamp is provided only roll back 1 day
        count = 0
        while True:
            ticker_info = requests.get(
                GEMINI_BASE_URL + f"/trades/{symbol}",
                params={
                    "timestamp": int(((timestamp - time_back).timestamp() * 1000)),
                    "limit_trades": LIMIT_TRADE_HISTORY,
                },
            ).json()
            time_back = time_back + timedelta(hours=1)
            if len(ticker_info) > 0:
                break
            count += 1
            if count == max_tries:
                break
        avg_price = sum([float(t["price"]) for t in ticker_info]) / LIMIT_TRADE_HISTORY
        price = Decimal(1) / Decimal(avg_price) if is_selling else Decimal(avg_price)
        return price
