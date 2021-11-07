import logging
import uuid
from datetime import datetime
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import (
    ADMIN_UUID,
    PAGINATION_LIMIT,
    SECP256K1_ALTERNATIVE_GENERATOR,
)
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid
from petlib.bn import Bn
from protobufs.audit_pb2 import Key as KeyPB2
from protobufs.institution.auditGenKey_pb2 import (
    AddKeyToAuditRequest,
    AddKeyToAuditResponse,
    GetKeyRequest,
    GetKeyResponse,
    ListKeysByAuditRequest,
    ListKeysByAuditResponse,
    ListKeysNotInAuditRequest,
    ListKeysNotInAuditResponse,
)
from protobufs.institution.auditGenKey_pb2_grpc import (
    AuditGenKeyServicer,
    add_AuditGenKeyServicer_to_server,
)
from sqlalchemy import or_
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.audit import Audit
from backend.sql.key import Key
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_KEYS_BY_AUDIT_NEXT_TOKEN_NAME = "ListKeysByAudit"
LIST_KEYS_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListKeysNotInAudit"


class ListKeysByAudit(
    ListRPC[
        ListKeysByAuditRequest,
        ListKeysByAuditResponse,
        ListKeysByAuditRequest.Request,
        ListKeysByAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_KEYS_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeysByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeysByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeysByAuditResponse.Response]:
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
        request: ListKeysByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeysByAuditResponse.Response]:
        with self._sessionmaker() as session:
            keys_for_audit = (
                session.query(Key)
                .filter(
                    Key.audit_publish_version == request.auditVersion,
                    Key.add_to_audit_timestamp <= initial_request_timestamp,
                )
                .order_by(Key.add_to_audit_timestamp)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            key_metadata_list: List[ListKeysByAuditResponse.Response] = []

            for key in keys_for_audit:
                asset_ownership_commitment = (
                    Bn(key.ownership_s) * key.permuted_secp256k1_public_key
                    + key.ownership_r * SECP256K1_ALTERNATIVE_GENERATOR
                ).export()
                key_pb2 = KeyPB2(
                    keyId=key.uuid.bytes,
                    publicKey=key.secp256k1_public_key.export(),
                    permutedPublicKey=key.permuted_secp256k1_public_key.export(),
                    permutationNIZK=key.permutation_nizk.serialize(),
                    assetOwnershipCommitment=asset_ownership_commitment,
                    assetOwnershipNIZK=key.ownership_nizk.serialize(),
                    auditVersion=key.audit_publish_version,
                )
                key_metadata_list.append(ListKeysByAuditResponse.Response(key=key_pb2))
            return key_metadata_list


class ListKeysNotInAudit(
    ListRPC[
        ListKeysNotInAuditRequest,
        ListKeysNotInAuditResponse,
        ListKeysNotInAuditRequest.Request,
        ListKeysNotInAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_KEYS_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeysNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeysNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeysNotInAuditResponse.Response]:
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
        request: ListKeysNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeysNotInAuditResponse.Response]:

        with self._sessionmaker() as session:
            keys_for_audit = (
                session.query(Key)
                .filter(
                    or_(  # back-calculate what wasn't in an audit at this timestamp
                        Key.add_to_audit_timestamp.is_(None),
                        Key.add_to_audit_timestamp > initial_request_timestamp,
                    ),
                    Key.created_at <= initial_request_timestamp,
                )
                .order_by(Key.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            key_metadata_list: List[ListKeysNotInAuditResponse.Response] = []

            for key in keys_for_audit:
                key_metadata_list.append(ListKeysNotInAuditResponse.Response(keyId=key.key_uuid.bytes))
            return key_metadata_list


class AuditGenKeyService(AuthenticatedServicer, AuditGenKeyServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._jwt_client = jwt_client
        add_AuditGenKeyServicer_to_server(self, server)
        self._list_keys_by_audit = ListKeysByAudit(jwt_client, sessionmaker)
        self._list_keys_not_in_audit = ListKeysNotInAudit(jwt_client, sessionmaker)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListKeysByAudit(
        self,
        request: ListKeysByAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListKeysByAuditResponse:
        return self._list_keys_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def ListKeysNotInAudit(
        self,
        request: ListKeysNotInAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListKeysNotInAuditResponse:
        return self._list_keys_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddKeyToAudit(
        self,
        request: AddKeyToAuditRequest,
        context: grpc.ServicerContext,
    ) -> AddKeyToAuditResponse:
        key_uuid = bytes_to_uuid(request.keyId)
        audit_version = request.auditVersion
        with self._sessionmaker() as session:
            # lock the audit
            ignored_audit = (
                session.query(Audit)
                .filter(Audit.version_number == request.auditVersion, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update(read=True)  # TODO we want nowait
                .one()
            )

            # update key's audit version in DB
            key = (
                session.query(Key)
                .filter(
                    Key.key_uuid == key_uuid,
                    Key.audit_publish_version.is_(None),
                )
                .populate_existing()
                .with_for_update()
                .one()
            )
            key.audit_publish_version = audit_version
            key.add_to_audit_timestamp = get_current_datetime()
            session.commit()

            asset_ownership_commitment = (
                Bn(key.ownership_s) * key.permuted_secp256k1_public_key
                + key.ownership_r * SECP256K1_ALTERNATIVE_GENERATOR
            ).export()

            return AddKeyToAuditResponse(
                key=KeyPB2(
                    keyId=key.key_uuid.bytes,
                    publicKey=key.secp256k1_public_key.export(),
                    permutedPublicKey=key.permuted_secp256k1_public_key.export(),
                    permutationNIZK=key.permutation_nizk.serialize(),
                    auditVersion=key.audit_publish_version,
                    assetOwnershipCommitment=asset_ownership_commitment,
                    assetOwnershipNIZK=key.ownership_nizk.serialize(),
                )
            )

    @admin_authenticated
    def GetKey(
        self,
        request: GetKeyRequest,
        context: grpc.ServicerContext,
    ) -> GetKeyResponse:
        key_uuid = bytes_to_uuid(request.keyId)
        with self._sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            if key.audit_publish_version is None:
                context.abort(grpc.StatusCode.NOT_FOUND, "key not in any audit")
                raise ValueError("key not in audit")
            asset_ownership_commitment = (
                Bn(key.ownership_s) * key.permuted_secp256k1_public_key
                + key.ownership_r * SECP256K1_ALTERNATIVE_GENERATOR
            ).export()
            return GetKeyResponse(
                key=KeyPB2(
                    keyId=key.uuid.bytes,
                    publicKey=key.secp256k1_public_key.export(),
                    permutedPublicKey=key.permuted_secp256k1_public_key.export(),
                    permutationNIZK=key.permutation_nizk.serialize(),
                    auditVersion=key.audit_publish_version,
                    assetOwnershipNIZK=key.ownership_nizk.serialize(),
                    assetOwnershipCommitment=asset_ownership_commitment,
                )
            )
