import logging
import uuid
from datetime import datetime
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import ADMIN_UUID, PAGINATION_LIMIT
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid
from protobufs.audit_pb2 import UserKey as UserKeyPB2
from protobufs.institution.auditGenUserKey_pb2 import (
    AddUserKeyToAuditRequest,
    AddUserKeyToAuditResponse,
    GetUserKeyRequest,
    GetUserKeyResponse,
    ListUserKeysByAuditRequest,
    ListUserKeysByAuditResponse,
    ListUserKeysNotInAuditRequest,
    ListUserKeysNotInAuditResponse,
)
from protobufs.institution.auditGenUserKey_pb2_grpc import (
    AuditGenUserKeyServicer,
    add_AuditGenUserKeyServicer_to_server,
)
from sqlalchemy import or_
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.audit import Audit
from backend.sql.user_key import UserKey
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_USER_KEYS_BY_AUDIT_NEXT_TOKEN_NAME = "ListUserKeysByAudit"
LIST_USER_KEYS_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListUserKeysNotInAudit"


class ListUserKeysByAudit(
    ListRPC[
        ListUserKeysByAuditRequest,
        ListUserKeysByAuditResponse,
        ListUserKeysByAuditRequest.Request,
        ListUserKeysByAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_USER_KEYS_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListUserKeysByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListUserKeysByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserKeysByAuditResponse.Response]:
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
        request: ListUserKeysByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserKeysByAuditResponse.Response]:

        with self._sessionmaker() as session:
            keys_for_audit = (
                session.query(UserKey)
                .filter(
                    UserKey.audit_publish_version == request.auditVersion,
                    UserKey.add_to_audit_timestamp <= initial_request_timestamp,
                )
                .order_by(UserKey.add_to_audit_timestamp)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            user_key_list: List[ListUserKeysByAuditResponse.Response] = []

            for key in keys_for_audit:
                key_metadata = UserKeyPB2(
                    keyId=key.user_key_uuid.bytes,
                    userId=key.user_uuid.bytes,
                    publicKey=key.public_key,
                    credentialId=key.credential_id,
                    auditVersion=key.audit_publish_version,
                    credentialType=key.credential_type,
                )
                user_key_list.append(ListUserKeysByAuditResponse.Response(userKey=key_metadata))

        return user_key_list


class ListUserKeysNotInAudit(
    ListRPC[
        ListUserKeysNotInAuditRequest,
        ListUserKeysNotInAuditResponse,
        ListUserKeysNotInAuditRequest.Request,
        ListUserKeysNotInAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_USER_KEYS_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListUserKeysNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListUserKeysNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserKeysNotInAuditResponse.Response]:
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
        request: ListUserKeysNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserKeysNotInAuditResponse.Response]:

        with self._sessionmaker() as session:
            keys_for_audit = (
                session.query(UserKey)
                .filter(
                    or_(  # back-calculate what wasn't in an audit at this timestamp
                        UserKey.add_to_audit_timestamp.is_(None),
                        UserKey.add_to_audit_timestamp > initial_request_timestamp,
                    ),
                    UserKey.created_at <= initial_request_timestamp,
                )
                .order_by(UserKey.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            user_key_list: List[ListUserKeysNotInAuditResponse.Response] = []

            for key in keys_for_audit:
                user_key_list.append(ListUserKeysNotInAuditResponse.Response(userKeyId=key.user_key_uuid.bytes))
        return user_key_list


class AuditGenUserKeyService(AuditGenUserKeyServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        add_AuditGenUserKeyServicer_to_server(self, server)
        self._jwt_client = jwt_client
        self._list_user_keys_by_audit = ListUserKeysByAudit(jwt_client, sessionmaker)
        self._list_user_keys_not_in_audit = ListUserKeysNotInAudit(jwt_client, sessionmaker)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListUserKeysByAudit(
        self,
        request: ListUserKeysByAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListUserKeysByAuditResponse:
        return self._list_user_keys_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def ListUserKeysNotInAudit(
        self,
        request: ListUserKeysNotInAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListUserKeysNotInAuditResponse:
        return self._list_user_keys_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddUserKeyToAudit(
        self,
        request: AddUserKeyToAuditRequest,
        context: grpc.ServicerContext,
    ) -> AddUserKeyToAuditResponse:
        user_key_uuid = bytes_to_uuid(request.keyId)
        audit_publish_version = request.auditVersion
        with self._sessionmaker() as session:
            ignored_audit = (
                session.query(Audit)
                .filter(Audit.version_number == request.auditVersion, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update(read=True)  # TODO we want nowait
                .one()
            )

            user_key = (
                session.query(UserKey)
                .filter(UserKey.user_key_uuid == user_key_uuid, UserKey.audit_publish_version.is_(None))
                .populate_existing()
                .with_for_update()
                .one()
            )

            user_key.audit_publish_version = audit_publish_version
            user_key.add_to_audit_timestamp = get_current_datetime()

            key = UserKeyPB2(
                keyId=user_key.user_key_uuid.bytes,
                userId=user_key.user_uuid.bytes,
                publicKey=user_key.public_key,
                credentialId=user_key.credential_id,
                credentialType=user_key.credential_type,
                auditVersion=audit_publish_version,
            )
            session.commit()
            return AddUserKeyToAuditResponse(userKey=key)

    @admin_authenticated
    def GetUserKey(
        self,
        request: GetUserKeyRequest,
        context: grpc.ServicerContext,
    ) -> GetUserKeyResponse:
        with self._sessionmaker() as session:
            user_key_uuid = bytes_to_uuid(request.keyId)
            updated_key_metadata = (
                session.query(UserKey)
                .filter(UserKey.user_key_uuid == user_key_uuid, UserKey.audit_publish_version.isnot(None))
                .one()
            )

            key = UserKeyPB2(
                keyId=updated_key_metadata.user_key_uuid.bytes,
                userId=updated_key_metadata.user_uuid.bytes,
                publicKey=updated_key_metadata.public_key,
                credentialId=updated_key_metadata.credential_id,
                credentialType=updated_key_metadata.credential_type,
                auditVersion=updated_key_metadata.audit_publish_version,
            )

            return GetUserKeyResponse(userKey=key)
