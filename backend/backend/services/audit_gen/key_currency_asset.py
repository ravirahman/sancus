import logging
import uuid
from datetime import datetime
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import (
    ADMIN_UUID,
    CURRENCY_PRECISIONS,
    CURRENCY_TO_BLOCKCHAIN,
    PAGINATION_LIMIT,
    SECP256K1_ORDER,
    Currency,
)
from common.utils.uuid import bytes_to_uuid
from common.utils.zk.key_amount import create_key_amount_commitment
from petlib.bn import Bn
from protobufs.audit_pb2 import KeyCurrencyAsset
from protobufs.institution.auditGenKeyCurrencyAsset_pb2 import (
    AddKeyCurrencyAssetToAuditRequest,
    AddKeyCurrencyAssetToAuditResponse,
    GetKeyCurrencyAssetRequest,
    GetKeyCurrencyAssetResponse,
    ListKeyCurrencyAssetsByAuditRequest,
    ListKeyCurrencyAssetsByAuditResponse,
    ListKeyCurrencyAssetsNotInAuditRequest,
    ListKeyCurrencyAssetsNotInAuditResponse,
)
from protobufs.institution.auditGenKeyCurrencyAsset_pb2_grpc import (
    AuditGenKeyCurrencyAssetServicer,
    add_AuditGenKeyCurrencyAssetServicer_to_server,
)
from sqlalchemy import and_, or_
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.audit import Audit
from backend.sql.audit_currency_asset import AuditCurrencyAsset
from backend.sql.audit_key_currency_asset import AuditKeyCurrencyAsset
from backend.sql.key import Key
from backend.sql.key_currency_account import KeyCurrencyAccount
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.key_client import KeyClient
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_KEY_CURRENCY_ASSETS_BY_AUDIT_NEXT_TOKEN_NAME = "ListKeyCurrencyAssetsByAudit"
LIST_KEY_CURRENCY_ASSETS_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListKeyCurrencyAssetsNotInAudit"


class ListKeyCurrencyAssetsByAudit(
    ListRPC[
        ListKeyCurrencyAssetsByAuditRequest,
        ListKeyCurrencyAssetsByAuditResponse,
        ListKeyCurrencyAssetsByAuditRequest.Request,
        ListKeyCurrencyAssetsByAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker, key_client: KeyClient):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker
        self._key_client = key_client

    next_token_name = LIST_KEY_CURRENCY_ASSETS_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeyCurrencyAssetsByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyCurrencyAssetsByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyCurrencyAssetsByAuditResponse.Response]:
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
        request: ListKeyCurrencyAssetsByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyCurrencyAssetsByAuditResponse.Response]:
        with self._sessionmaker() as session:
            key_currency_assets = (
                session.query(AuditKeyCurrencyAsset)
                .filter(
                    AuditKeyCurrencyAsset.audit_version == request.auditVersion,
                    AuditKeyCurrencyAsset.created_at <= initial_request_timestamp,
                )
                .order_by(AuditKeyCurrencyAsset.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )

        responses: List[ListKeyCurrencyAssetsByAuditResponse.Response] = []
        for key_currency_asset in key_currency_assets:
            responses.append(
                ListKeyCurrencyAssetsByAuditResponse.Response(
                    keyCurrencyAsset=KeyCurrencyAsset(
                        keyId=key_currency_asset.key_uuid.bytes,
                        currency=key_currency_asset.currency.name,
                        p=key_currency_asset.p.export(),
                        nizk=key_currency_asset.nizk.serialize(),
                        auditVersion=request.auditVersion,
                    )
                )
            )
        return responses


class ListKeyCurrencyAssetsNotInAudit(
    ListRPC[
        ListKeyCurrencyAssetsNotInAuditRequest,
        ListKeyCurrencyAssetsNotInAuditResponse,
        ListKeyCurrencyAssetsNotInAuditRequest.Request,
        ListKeyCurrencyAssetsNotInAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_KEY_CURRENCY_ASSETS_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeyCurrencyAssetsNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyCurrencyAssetsNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyCurrencyAssetsNotInAuditResponse.Response]:
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
        request: ListKeyCurrencyAssetsNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyCurrencyAssetsNotInAuditResponse.Response]:
        response: List[ListKeyCurrencyAssetsNotInAuditResponse.Response] = []
        with self._sessionmaker() as session:
            audit = session.query(Audit).filter(Audit.version_number == request.auditVersion).one()
            missing_key_account_commitments = (
                session.query(KeyCurrencyAccount)
                .filter(
                    KeyCurrencyAccount.created_at < initial_request_timestamp,
                    or_(
                        *[
                            and_(
                                KeyCurrencyAccount.currency == currency,
                                KeyCurrencyAccount.initial_balance_block_number
                                < audit.get_block(CURRENCY_TO_BLOCKCHAIN[currency]),
                            )
                            for currency in Currency
                        ]
                    ),
                )
                .order_by(KeyCurrencyAccount.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            for kca in missing_key_account_commitments:
                response.append(
                    ListKeyCurrencyAssetsNotInAuditResponse.Response(
                        keyId=kca.key_uuid.bytes,
                        currency=kca.currency.name,
                    )
                )
        return response


class AuditGenKeyCurrencyAssetService(AuditGenKeyCurrencyAssetServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
        key_client: KeyClient,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        add_AuditGenKeyCurrencyAssetServicer_to_server(self, server)
        self._key_client = key_client
        self._jwt_client = jwt_client
        self._list_key_currency_assets_by_audit = ListKeyCurrencyAssetsByAudit(jwt_client, sessionmaker, key_client)
        self._list_key_currency_assets_not_in_audit = ListKeyCurrencyAssetsNotInAudit(jwt_client, sessionmaker)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListKeyCurrencyAssetsByAudit(
        self, request: ListKeyCurrencyAssetsByAuditRequest, context: grpc.ServicerContext
    ) -> ListKeyCurrencyAssetsByAuditResponse:
        return self._list_key_currency_assets_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def ListKeyCurrencyAssetsNotInAudit(
        self, request: ListKeyCurrencyAssetsNotInAuditRequest, context: grpc.ServicerContext
    ) -> ListKeyCurrencyAssetsNotInAuditResponse:
        return self._list_key_currency_assets_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddKeyCurrencyAssetToAudit(
        self, request: AddKeyCurrencyAssetToAuditRequest, context: grpc.ServicerContext
    ) -> AddKeyCurrencyAssetToAuditResponse:
        key_uuid = bytes_to_uuid(request.keyId)
        currency = Currency[request.currency]
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            # just reading here; no need to lock
            audit = session.query(Audit).filter(Audit.version_number == request.auditVersion).one()

            key_currency_account, key = (
                session.query(KeyCurrencyAccount, Key)
                .filter(
                    KeyCurrencyAccount.key_uuid == key_uuid,
                    KeyCurrencyAccount.currency == currency,
                    Key.key_uuid == KeyCurrencyAccount.key_uuid,
                )
                .one()
            )
            if key.audit_publish_version is None or key.audit_publish_version > request.auditVersion:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"key {key.key_uuid} not yet added to audit")
                raise ValueError(f"key {key.key_uuid} not yet added to audit")
            block_number = audit.get_block(CURRENCY_TO_BLOCKCHAIN[currency])
            if key_currency_account.initial_balance_block_number >= block_number:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, "key is too recent")
                raise RuntimeError("key is too recent")

            x = key.permuted_private_key
            y = key.permuted_secp256k1_public_key
            s = Bn(key_currency_account.account_uuid is not None)
            x_hat = s if s == Bn(0) else s * x
            t = key.ownership_r

        balance = self._key_client.get_balance(key_uuid, currency, block_number)

        amount = Bn.from_decimal(str(int(balance * CURRENCY_PRECISIONS[currency])))

        v = SECP256K1_ORDER.random()

        p, ignored_l, nizk = create_key_amount_commitment(amount=amount, v=v, t=t, y=y, x_hat=x_hat)
        with self._sessionmaker() as session:
            ignored_audit = (
                session.query(Audit)
                .filter(Audit.version_number == request.auditVersion, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update(read=True)  # TODO we want nowait
                .one()
            )
            session.add(
                AuditKeyCurrencyAsset(
                    audit_version=audit_version,
                    key_uuid=key_uuid,
                    currency=currency,
                    v=v,
                    p=p,
                    nizk=nizk,
                )
            )
            audit_currency_asset = (
                session.query(AuditCurrencyAsset)
                .filter(
                    AuditCurrencyAsset.audit_version == audit_version,
                    AuditCurrencyAsset.currency == currency,
                )
                .populate_existing()
                .with_for_update()
                .one()
            )

            audit_currency_asset.cumulative_assets = audit_currency_asset.cumulative_assets + s * amount
            audit_currency_asset.cumulative_v = (audit_currency_asset.cumulative_v + v) % SECP256K1_ORDER
            session.commit()

        return AddKeyCurrencyAssetToAuditResponse(
            keyCurrencyAsset=KeyCurrencyAsset(
                keyId=key_uuid.bytes,
                currency=currency.name,
                p=p.export(),
                nizk=nizk.serialize(),
                auditVersion=audit_version,
            )
        )

    @admin_authenticated
    def GetKeyCurrencyAsset(
        self, request: GetKeyCurrencyAssetRequest, context: grpc.ServicerContext
    ) -> GetKeyCurrencyAssetResponse:
        key_uuid = bytes_to_uuid(request.keyId)
        currency = Currency[request.currency]
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            key_currency_asset = (
                session.query(AuditKeyCurrencyAsset)
                .filter(
                    AuditKeyCurrencyAsset.audit_version == request.auditVersion,
                    AuditKeyCurrencyAsset.key_uuid == key_uuid,
                    AuditKeyCurrencyAsset.currency == currency,
                )
                .one()
            )

            return GetKeyCurrencyAssetResponse(
                keyCurrencyAsset=KeyCurrencyAsset(
                    keyId=key_uuid.bytes,
                    currency=currency.name,
                    p=key_currency_asset.p.export(),
                    nizk=key_currency_asset.nizk.serialize(),
                    auditVersion=audit_version,
                )
            )
