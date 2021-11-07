import logging
import uuid
from datetime import datetime
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import (
    ADMIN_UUID,
    CURRENCY_TO_BLOCKCHAIN,
    PAGINATION_LIMIT,
    SECP256K1_ALTERNATIVE_GENERATOR,
)
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid
from petlib.bn import Bn
from protobufs.audit_pb2 import KeyAccount as KeyAccountPB2
from protobufs.institution.auditGenKeyAccount_pb2 import (
    AddKeyAccountToAuditRequest,
    AddKeyAccountToAuditResponse,
    GetKeyAccountRequest,
    GetKeyAccountResponse,
    ListKeyAccountsByAuditRequest,
    ListKeyAccountsByAuditResponse,
    ListKeyAccountsNotInAuditRequest,
    ListKeyAccountsNotInAuditResponse,
)
from protobufs.institution.auditGenKeyAccount_pb2_grpc import (
    AuditGenKeyAccountServicer,
    add_AuditGenKeyAccountServicer_to_server,
)
from sqlalchemy import or_
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.audit import Audit
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_KEY_ACCOUNTS_BY_AUDIT_NEXT_TOKEN_NAME = "ListKeyAccountsByAudit"
LIST_KEY_ACCOUNTS_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListKeyAccountsNotInAudit"


class ListKeyAccountsByAudit(
    ListRPC[
        ListKeyAccountsByAuditRequest,
        ListKeyAccountsByAuditResponse,
        ListKeyAccountsByAuditRequest.Request,
        ListKeyAccountsByAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_KEY_ACCOUNTS_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeyAccountsByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyAccountsByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountsByAuditResponse.Response]:
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            try:
                session.query(Audit).filter(Audit.version_number == audit_version).one()
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "audit not found for provided version")
                raise ValueError("audit not found for provided version") from e
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
        request: ListKeyAccountsByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountsByAuditResponse.Response]:
        with self._sessionmaker() as session:
            key_accounts_and_keys_for_audit = (
                session.query(KeyAccountCommitment, Key)
                .filter(
                    KeyAccountCommitment.audit_publish_version == request.auditVersion,
                    KeyAccountCommitment.add_to_audit_timestamp <= initial_request_timestamp,
                    Key.key_uuid == KeyAccountCommitment.key_uuid,
                )
                .order_by(KeyAccountCommitment.add_to_audit_timestamp)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            key_accounts: List[ListKeyAccountsByAuditResponse.Response] = []

            for key_account, key in key_accounts_and_keys_for_audit:
                key_account_pb2 = KeyAccountPB2(
                    keyId=key_account.uuid.bytes,
                    accountId=key_account.account_uuid.bytes,
                    ownershipCommitment=(
                        Bn(key_account.s) * key.permuted_secp256k1_public_key
                        + key_account.r * SECP256K1_ALTERNATIVE_GENERATOR
                    ).export(),
                    ownershipNIZK=key_account.ownershipNIZK,
                    blockNumber=key_account.block_number,
                    auditVersion=key_account.audit_publish_version,
                )
                key_accounts.append(ListKeyAccountsByAuditResponse.Response(key=key_account_pb2))
            return key_accounts


class ListKeyAccountsNotInAudit(
    ListRPC[
        ListKeyAccountsNotInAuditRequest,
        ListKeyAccountsNotInAuditResponse,
        ListKeyAccountsNotInAuditRequest.Request,
        ListKeyAccountsNotInAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_KEY_ACCOUNTS_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeyAccountsNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyAccountsNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountsNotInAuditResponse.Response]:
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
        request: ListKeyAccountsNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountsNotInAuditResponse.Response]:

        with self._sessionmaker() as session:
            key_accounts_for_audit = (
                session.query(KeyAccountCommitment)
                .filter(
                    or_(  # back-calculate what wasn't in an audit at this timestamp
                        KeyAccountCommitment.add_to_audit_timestamp.is_(None),
                        KeyAccountCommitment.add_to_audit_timestamp > initial_request_timestamp,
                    ),
                    KeyAccountCommitment.created_at <= initial_request_timestamp,
                )
                .order_by(KeyAccountCommitment.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            key_accounts: List[ListKeyAccountsNotInAuditResponse.Response] = []

            for key_account in key_accounts_for_audit:
                key_accounts.append(
                    ListKeyAccountsNotInAuditResponse.Response(
                        keyId=key_account.key_uuid.bytes, accountId=key_account.account_uuid.bytes
                    )
                )
            return key_accounts


class AuditGenKeyAccountService(AuthenticatedServicer, AuditGenKeyAccountServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._jwt_client = jwt_client
        add_AuditGenKeyAccountServicer_to_server(self, server)
        self._list_key_accounts_by_audit = ListKeyAccountsByAudit(jwt_client, sessionmaker)
        self._list_key_accounts_not_in_audit = ListKeyAccountsNotInAudit(jwt_client, sessionmaker)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListKeyAccountsByAudit(
        self,
        request: ListKeyAccountsByAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListKeyAccountsByAuditResponse:
        return self._list_key_accounts_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def ListKeyAccountsNotInAudit(
        self,
        request: ListKeyAccountsNotInAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListKeyAccountsNotInAuditResponse:
        return self._list_key_accounts_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddKeyAccountToAudit(
        self,
        request: AddKeyAccountToAuditRequest,
        context: grpc.ServicerContext,
    ) -> AddKeyAccountToAuditResponse:
        key_uuid = bytes_to_uuid(request.keyId)
        account_uuid = bytes_to_uuid(request.accountId)
        audit_version = request.auditVersion
        with self._sessionmaker() as session:
            # flush and lock the row:
            audit = (
                session.query(Audit)
                .filter(Audit.version_number == request.auditVersion, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update(read=True)  # TODO we want nowait
                .one()
            )

            account = session.query(Account).filter(Account.uuid == account_uuid).one()
            if account.audit_version is None or account.audit_version > audit_version:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"account {account.uuid} not yet added to audit")
                raise ValueError(f"account {account.uuid} not yet added to audit")
            blockchain = CURRENCY_TO_BLOCKCHAIN[account.currency]
            audit_block = audit.get_block(blockchain)
            key_account = (
                session.query(KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.key_uuid == key_uuid,
                    KeyAccountCommitment.account_uuid == account_uuid,
                    KeyAccountCommitment.audit_publish_version.is_(None),
                )
                .populate_existing()
                .with_for_update()
                .one()
            )
            if key_account.block_number is None:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, "key_account has no block number")
                raise ValueError("key_account has no block number")

            if key_account.block_number > audit_block:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, "key_account block is ahead of audit")
                raise ValueError("key_account block is ahead of audit")

            # update KeyAccount's audit version in DB
            key_account.audit_publish_version = audit_version
            key_account.add_to_audit_timestamp = get_current_datetime()
            key = session.query(Key).filter(Key.key_uuid == key_account.key_uuid).one()
            if key.audit_publish_version is None or key.audit_publish_version > audit_version:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"key {key.key_uuid} not yet added to audit")
                raise ValueError(f"account {key.key_uuid} not yet added to audit")

            session.commit()

            return AddKeyAccountToAuditResponse(
                keyAccount=KeyAccountPB2(
                    keyId=key_account.key_uuid.bytes,
                    accountId=key_account.account_uuid.bytes,
                    ownershipCommitment=(
                        Bn(key_account.s) * key.permuted_secp256k1_public_key
                        + key_account.r * SECP256K1_ALTERNATIVE_GENERATOR
                    ).export(),
                    ownershipNIZK=key_account.nizk.serialize(),
                    blockNumber=key_account.block_number,
                    auditVersion=key_account.audit_publish_version,
                )
            )

    @admin_authenticated
    def GetKeyAccount(
        self,
        request: GetKeyAccountRequest,
        context: grpc.ServicerContext,
    ) -> GetKeyAccountResponse:
        account_uuid = bytes_to_uuid(request.accountId)
        key_uuid = bytes_to_uuid(request.keyId)
        with self._sessionmaker() as session:
            key_account, key = (
                session.query(KeyAccountCommitment, Key)
                .filter(
                    KeyAccountCommitment.account_uuid == account_uuid,
                    KeyAccountCommitment.key_uuid == key_uuid,
                    Key.key_uuid == KeyAccountCommitment.key_uuid,
                )
                .one()
            )
            if key_account.audit_publish_version is None:
                context.abort(grpc.StatusCode.NOT_FOUND, "KeyAccount not found for user or KeyAccount already updated")
                raise ValueError("KeyAccount not in audit")
            return GetKeyAccountResponse(
                keyAccount=KeyAccountPB2(
                    keyId=key_account.uuid.bytes,
                    accountId=key_account.account_uuid.bytes,
                    ownershipCommitment=(
                        Bn(key_account.s) * key.permuted_secp256k1_public_key
                        + key_account.r * SECP256K1_ALTERNATIVE_GENERATOR
                    ).export(),
                    ownershipNIZK=key_account.ownershipNIZK,
                    blockNumber=key_account.block_number,
                    auditVersion=key_account.audit_publish_version,
                )
            )
