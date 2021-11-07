import unittest
import uuid

from common.constants import Currency
from common.utils.datetime import get_current_datetime
from protobufs.institution.marketdata_pb2 import ExchangeRate

from backend.utils.jwt_client import JWTClient, JWTException
from tests.fixtures import MOCK_JWT_CONFIG, MOCK_USER_UUID


class TestJwtClient(unittest.TestCase):
    jwt_client: JWTClient

    @classmethod
    def setUpClass(cls) -> None:
        cls.jwt_client = JWTClient(MOCK_JWT_CONFIG)

    def test_issue_decode_auth(self) -> None:
        token = self.jwt_client.issue_auth_jwt(MOCK_USER_UUID)
        decoded_user_uuid = self.jwt_client.decode_auth_jwt(token)
        self.assertEqual(decoded_user_uuid, MOCK_USER_UUID)

    def test_issue_decode_rate(self) -> None:
        exchange_rate = ExchangeRate(fromCurrency=Currency.GUSD.name, toCurrency=Currency.BTC.name, rate="30000.00")
        token = self.jwt_client.issue_rate_jwt(MOCK_USER_UUID, exchange_rate, get_current_datetime())
        decoded_exchange_rate, exchange_rate_expiration = self.jwt_client.decode_rate_jwt(MOCK_USER_UUID, token)
        self.assertEqual(exchange_rate, decoded_exchange_rate)
        self.assertGreater(exchange_rate_expiration, get_current_datetime())

    def test_issue_rate_invalid_user(self) -> None:
        exchange_rate = ExchangeRate(fromCurrency=Currency.GUSD.name, toCurrency=Currency.BTC.name, rate="30000.00")
        token = self.jwt_client.issue_rate_jwt(MOCK_USER_UUID, exchange_rate, get_current_datetime())
        wrong_user_uuid = uuid.uuid4()
        with self.assertRaises(JWTException):
            self.jwt_client.decode_rate_jwt(wrong_user_uuid, token)


if __name__ == "__main__":
    unittest.main()
