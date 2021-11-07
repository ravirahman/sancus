import logging
import uuid
from datetime import datetime
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import ADMIN_UUID, PAGINATION_LIMIT
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid
from protobufs.audit_pb2 import Account as AccountPB2
from protobufs.institution.auditGenAccount_pb2 import (
    AddAccountToAuditRequest,
    AddAccountToAuditResponse,
    GetAccountRequest,
    GetAccountResponse,
    ListAccountsByAuditRequest,
    ListAccountsByAuditResponse,
    ListAccountsNotInAuditRequest,
    ListAccountsNotInAuditResponse,
)
from protobufs.institution.auditGenAccount_pb2_grpc import (
    AuditGenAccountServicer,
    add_AuditGenAccountServicer_to_server,
)
from sqlalchemy import or_
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.audit import Audit
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_ACCOUNTS_BY_AUDIT_NEXT_TOKEN_NAME = "ListAccountsByAudit"
LIST_ACCOUNTS_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListAccountsNotInAudit"


class ListAccountsByAudit(
    ListRPC[
        ListAccountsByAuditRequest,
        ListAccountsByAuditResponse,
        ListAccountsByAuditRequest.Request,
        ListAccountsByAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_ACCOUNTS_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListAccountsByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAccountsByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountsByAuditResponse.Response]:
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            try:
                session.query(Audit).filter(Audit.version_number == audit_version).one()
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "audit not found for provided version")
                raise ValueError("audit not found for provided version") from e

        return self.handle_subsequent_request(
            request=request,
            initial_request_timestamp=initial_request_timestamp,
            offset=0,
            context=context,
            user_uuid=user_uuid,
        )

    def handle_subsequent_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAccountsByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountsByAuditResponse.Response]:
        with self._sessionmaker() as session:
            accounts_for_audit = (
                session.query(Account)
                .filter(
                    Account.audit_version == request.auditVersion,
                    Account.add_to_audit_timestamp <= initial_request_timestamp,
                )
                .order_by(Account.add_to_audit_timestamp)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            account_metadata_list: List[ListAccountsByAuditResponse.Response] = []

            for account in accounts_for_audit:
                account_pb2 = AccountPB2(
                    accountId=account.uuid.bytes,
                    userId=account.user_uuid.bytes,
                    accountType=account.account_type,
                    currency=account.currency.name,
                    auditVersion=account.audit_version,
                )
                account_metadata_list.append(ListAccountsByAuditResponse.Response(account=account_pb2))
            return account_metadata_list


class ListAccountsNotInAudit(
    ListRPC[
        ListAccountsNotInAuditRequest,
        ListAccountsNotInAuditResponse,
        ListAccountsNotInAuditRequest.Request,
        ListAccountsNotInAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_ACCOUNTS_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListAccountsNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAccountsNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountsNotInAuditResponse.Response]:
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
        request: ListAccountsNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountsNotInAuditResponse.Response]:
        with self._sessionmaker() as session:
            accounts_for_audit = (
                session.query(Account)
                .filter(
                    or_(  # back-calculate what wasn't in an audit at this timestamp
                        Account.add_to_audit_timestamp.is_(None),
                        Account.add_to_audit_timestamp > initial_request_timestamp,
                    ),
                    Account.created_at <= initial_request_timestamp,
                )
                .order_by(Account.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            account_metadata_list: List[ListAccountsNotInAuditResponse.Response] = []

            for account in accounts_for_audit:
                account_metadata_list.append(ListAccountsNotInAuditResponse.Response(accountId=account.uuid.bytes))
            return account_metadata_list


class AuditGenAccountService(AuthenticatedServicer, AuditGenAccountServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._jwt_client = jwt_client
        add_AuditGenAccountServicer_to_server(self, server)
        self._list_accounts_by_audit = ListAccountsByAudit(jwt_client, sessionmaker)
        self._list_accounts_not_in_audit = ListAccountsNotInAudit(jwt_client, sessionmaker)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListAccountsByAudit(
        self,
        request: ListAccountsByAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListAccountsByAuditResponse:
        return self._list_accounts_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def ListAccountsNotInAudit(
        self,
        request: ListAccountsNotInAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListAccountsNotInAuditResponse:
        return self._list_accounts_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddAccountToAudit(
        self,
        request: AddAccountToAuditRequest,
        context: grpc.ServicerContext,
    ) -> AddAccountToAuditResponse:
        account_uuid = bytes_to_uuid(request.accountId)
        audit_version = request.auditVersion
        with self._sessionmaker() as session:
            ignored_audit = (
                session.query(Audit)
                .filter(Audit.version_number == request.auditVersion, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update(read=True)  # TODO we want nowait
                .one()
            )

            account = (
                session.query(Account)
                .filter(Account.uuid == account_uuid, Account.audit_version.is_(None))
                .populate_existing()
                .with_for_update()
                .one()
            )
            account.audit_version = audit_version
            account.add_to_audit_timestamp = get_current_datetime()
            # update account's audit version in DB
            session.commit()

            updated_account_metadata = session.query(Account).filter(Account.uuid == account_uuid).one()
            return AddAccountToAuditResponse(
                account=AccountPB2(
                    accountId=updated_account_metadata.uuid.bytes,
                    userId=updated_account_metadata.user_uuid.bytes,
                    accountType=updated_account_metadata.account_type,
                    currency=updated_account_metadata.currency.name,
                    auditVersion=updated_account_metadata.audit_version,
                )
            )

    @admin_authenticated
    def GetAccount(
        self,
        request: GetAccountRequest,
        context: grpc.ServicerContext,
    ) -> GetAccountResponse:
        account_uuid = bytes_to_uuid(request.accountId)
        with self._sessionmaker() as session:
            account = session.query(Account).filter(Account.uuid == account_uuid).one()
            if account.audit_version is None:
                context.abort(grpc.StatusCode.NOT_FOUND, "account not found for user or account already updated")
                raise ValueError("account not in audit")
            return GetAccountResponse(
                account=AccountPB2(
                    accountId=account.uuid.bytes,
                    userId=account.user_uuid.bytes,
                    accountType=account.account_type,
                    currency=account.currency,
                    auditVersion=account.audit_version,
                )
            )
