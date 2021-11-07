import unittest
from decimal import Decimal

import grpc
from common.constants import Currency
from common.utils.datetime import datetime_to_protobuf, get_current_datetime
from common.utils.uuid import bytes_to_uuid
from google.protobuf.timestamp_pb2 import Timestamp
from protobufs.account_pb2 import AccountType
from protobufs.institution.account_pb2 import (
    ListAccountsRequest,
    ListTransactionsRequest,
    MakeAccountRequest,
    TransactionStatus,
    TransactionType,
)
from protobufs.institution.account_pb2_grpc import AccountStub

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.transaction import Transaction
from tests.base import BaseBackendTestCase
from tests.fixtures import MOCK_USER_UUID


class TestAccount(BaseBackendTestCase):
    account_stub: AccountStub
    channel: grpc.Channel
    backend: Backend

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.account_stub = AccountStub(cls.channel)

    def setUp(self) -> None:
        super().setUp()
        with self.backend.sessionmaker() as session:
            # just going to create a gusd balance and deposit record
            account = Account(
                user_uuid=MOCK_USER_UUID,
                currency=Currency.GUSD,
                account_type=AccountType.DEPOSIT_ACCOUNT,
                available_amount=Decimal("1"),
            )
            session.add(account)
            session.commit()
            assert account.uuid is not None
            transaction = Transaction(
                account_uuid=account.uuid,
                transaction_type=TransactionType.DEPOSIT,
                status=TransactionStatus.COMPLETED,
                amount=Decimal("1"),
            )
            session.add(transaction)
            session.commit()

            self.account_uuid = account.uuid
            self.transaction_uuid = transaction.uuid

    def test_list_accounts(self) -> None:
        req = ListAccountsRequest(
            request=ListAccountsRequest.Request(
                ids=[self.account_uuid.bytes],
                currencies=[Currency.GUSD.name],
                accountTypes=[AccountType.DEPOSIT_ACCOUNT, AccountType.LOAN_ACCOUNT],
            )
        )
        resp = self.account_stub.ListAccounts(req)
        self.assertEqual(len(resp.response), 1)
        account_response = resp.response[0]
        self.assertEqual(account_response.id, self.account_uuid.bytes)
        self.assertEqual(Decimal(account_response.availableAmount), Decimal("1"))

        req2 = ListAccountsRequest(nextToken=resp.nextToken)
        resp2 = self.account_stub.ListAccounts(req2)
        self.assertEqual(len(resp2.response), 0)
        self.assertEqual(resp2.nextToken, "")

    def test_list_transactions(self) -> None:
        from_timestamp = Timestamp(seconds=0, nanos=0)
        to_timestamp = datetime_to_protobuf(get_current_datetime())
        req = ListTransactionsRequest(
            request=ListTransactionsRequest.Request(
                accountId=self.account_uuid.bytes,
                transactionTypes=[TransactionType.DEPOSIT],
                fromTimestamp=from_timestamp,
                toTimestamp=to_timestamp,
            )
        )
        resp = self.account_stub.ListTransactions(req)
        self.assertEqual(len(resp.response), 1)
        transaction_response = resp.response[0]
        self.assertEqual(transaction_response.id, self.transaction_uuid.bytes)
        self.assertEqual(transaction_response.accountId, self.account_uuid.bytes)

        req2 = ListTransactionsRequest(nextToken=resp.nextToken)
        resp2 = self.account_stub.ListTransactions(req2)
        self.assertEqual(len(resp2.response), 0)
        self.assertEqual(resp2.nextToken, "")

    def test_make_account(self) -> None:
        req = MakeAccountRequest(accountType=AccountType.COLLATERAL_ACCOUNT, currency="GUSD")
        resp = self.account_stub.MakeAccount(req)
        with self.backend.sessionmaker() as session:
            session.query(Account).filter(Account.uuid == bytes_to_uuid(resp.accountId)).one()


if __name__ == "__main__":
    unittest.main()
