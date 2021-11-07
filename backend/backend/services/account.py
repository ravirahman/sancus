import logging
import uuid
from datetime import datetime
from typing import List, Sequence, Set, cast

import grpc
import sqlalchemy.orm
from common.constants import PAGINATION_LIMIT, Currency
from common.utils.datetime import datetime_to_protobuf, protobuf_to_datetime
from common.utils.uuid import bytes_to_uuid
from google.protobuf.any_pb2 import Any
from protobufs.account_pb2 import AccountType
from protobufs.institution.account_pb2 import (
    AccountResponse,
    ListAccountsRequest,
    ListAccountsResponse,
    ListTransactionsRequest,
    ListTransactionsResponse,
    MakeAccountRequest,
    MakeAccountResponse,
    TransactionResponse,
    TransactionType,
)
from protobufs.institution.account_pb2_grpc import (
    AccountServicer,
    add_AccountServicer_to_server,
)
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.transaction import Transaction
from backend.utils.jwt_client import AuthenticatedServicer, JWTClient, authenticated
from backend.utils.list_rpc import ListRPC
from backend.utils.webauthn_client import WebauthnClient

LOGGER = logging.getLogger(__name__)

LIST_TRANSACTION_HISTORY_NEXT_TOKEN_TYPE = "ListTransactionHistory"
LIST_ACCOUNTS_NEXT_TOKEN_TYPE = "ListAccounts"


class ListAccountsRPC(ListRPC[ListAccountsRequest, ListAccountsResponse, ListAccountsRequest.Request, AccountResponse]):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_ACCOUNTS_NEXT_TOKEN_TYPE
    list_response_type = ListAccountsResponse

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAccountsRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[AccountResponse]:
        return self.handle_subsequent_request(
            initial_request_timestamp=initial_request_timestamp,
            request=request,
            offset=0,
            context=context,
            user_uuid=user_uuid,
        )

    def handle_subsequent_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAccountsRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[AccountResponse]:
        filters = [Account.user_uuid == user_uuid]

        currencies: Set[Currency] = set()
        for currency_str in request.currencies:
            try:
                currency = Currency[currency_str]
            except KeyError as e:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid currency")
                raise ValueError("Invalid currency") from e
            if currency in currencies:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Duplicate currency")
                raise ValueError("Duplicate currency")
            currencies.add(currency)
        if len(currencies) > 0:
            filters.append(Account.currency.in_(currencies))

        account_types: "Set[AccountType.V]" = set()
        for account_type in request.accountTypes:
            if account_type == AccountType.INVALID_ACCOUNT_TYPE:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid account type")
                raise ValueError("Invalid account type")
            if account_type in account_types:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Duplicate account type")
                raise ValueError("Duplicate account type")
            account_types.add(account_type)
        if len(account_types) > 0:
            filters.append(Account.account_type.in_(account_types))

        account_pbs: List[AccountResponse] = []
        with self._sessionmaker() as session:
            accounts = (
                session.query(Account)
                .filter(*filters)
                .order_by(desc(Account.created_at))
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            for account in accounts:
                currency = cast(Currency, account.currency)
                account_pb = AccountResponse(
                    id=account.uuid.bytes,
                    accountType=account.account_type,
                    currency=currency.name,
                    availableAmount=str(account.available_amount.normalize()),
                    pendingAmount=str(account.pending_amount.normalize()),
                )
                account_pbs.append(account_pb)
        return account_pbs


class ListTransactionsRPC(
    ListRPC[ListTransactionsRequest, ListTransactionsResponse, ListTransactionsRequest.Request, TransactionResponse]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_TRANSACTION_HISTORY_NEXT_TOKEN_TYPE
    list_response_type = ListTransactionsResponse

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListTransactionsRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[TransactionResponse]:
        with self._sessionmaker() as session:
            account_uuid = bytes_to_uuid(request.accountId)
            try:
                session.query(Account).filter(
                    Account.user_uuid == user_uuid,
                    Account.uuid == account_uuid,
                ).one()
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Account {account_uuid} not found for user")
                raise ValueError("Account not found for user") from e
        return self.handle_subsequent_request(
            initial_request_timestamp=initial_request_timestamp,
            request=request,
            offset=0,
            context=context,
            user_uuid=user_uuid,
        )

    def handle_subsequent_request(
        self,
        initial_request_timestamp: datetime,
        request: ListTransactionsRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[TransactionResponse]:
        filters: List[object] = []
        account_uuid = bytes_to_uuid(request.accountId)
        filters.append(Transaction.account_uuid == account_uuid)
        from_timestamp = protobuf_to_datetime(request.fromTimestamp)
        to_timestamp = protobuf_to_datetime(request.toTimestamp)
        if from_timestamp >= to_timestamp:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "fromTimestamp >= toTimestamp")
            raise ValueError("fromTimestamp >= toTimestamp")
        filters.append(Transaction.timestamp >= from_timestamp)
        filters.append(Transaction.timestamp < to_timestamp)
        transaction_types: "Set[TransactionType.V]" = set()

        for transaction_type in request.transactionTypes:
            if transaction_type == TransactionType.INVALID_TRANSACTION_TYPE:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid transaction type")
                raise ValueError("Invalid transaction type")
            if transaction_type in transaction_types:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Duplicate transaction type")
                raise ValueError("Duplicate transaction type")
            transaction_types.add(transaction_type)
        if len(transaction_types) > 0:
            filters.append(Transaction.transaction_type.in_(transaction_types))

        transaction_pbs: List[TransactionResponse] = []

        with self._sessionmaker() as session:
            transactions = (
                session.query(Transaction)
                .filter(*filters)
                .order_by(desc(Transaction.timestamp))
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            for transaction in transactions:
                transaction_data = Any()
                if transaction_data.value != b"":
                    transaction_data.Pack(transaction.extra)

                transaction_pb = TransactionResponse(
                    id=transaction.uuid.bytes,
                    accountId=account_uuid.bytes,
                    status=transaction.status,
                    timestamp=datetime_to_protobuf(transaction.timestamp),
                    transactionType=transaction.transaction_type,
                    amount=str(transaction.amount.normalize()),
                    extra=transaction_data,
                )
                transaction_pbs.append(transaction_pb)
        return tuple(transaction_pbs)


class AccountService(AccountServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        webauthn_client: WebauthnClient,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._webauthn_client = webauthn_client
        self._jwt_client = jwt_client
        self._list_accounts_rpc = ListAccountsRPC(jwt_client, sessionmaker)
        self._list_transactions_rpc = ListTransactionsRPC(jwt_client, sessionmaker)
        add_AccountServicer_to_server(self, server)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @authenticated
    def ListAccounts(
        self,
        request: ListAccountsRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> ListAccountsResponse:
        return self._list_accounts_rpc(request, context, user_uuid)

    @authenticated
    def ListTransactions(
        self,
        request: ListTransactionsRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> ListTransactionsResponse:
        return self._list_transactions_rpc(request, context, user_uuid)

    @authenticated
    def MakeAccount(
        self, request: MakeAccountRequest, context: grpc.ServicerContext, user_uuid: uuid.UUID
    ) -> MakeAccountResponse:
        # allowed account types are collateral accounts and deposit accounts.
        currency = Currency[request.currency]
        account_type = request.accountType
        if account_type not in (AccountType.DEPOSIT_ACCOUNT, AccountType.COLLATERAL_ACCOUNT):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"invalid account type: {account_type}")
            raise ValueError(f"invalid account type: {account_type}")
        with self._sessionmaker() as session:
            account = Account(
                account_type=account_type,
                user_uuid=user_uuid,
                currency=currency,
            )
            session.add(account)
            session.commit()
            account_uuid = account.uuid
        return MakeAccountResponse(accountId=account_uuid.bytes)
