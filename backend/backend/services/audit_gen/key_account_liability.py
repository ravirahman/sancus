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
from protobufs.audit_pb2 import KeyAccountLiability
from protobufs.institution.auditGenKeyAccountLiability_pb2 import (
    AddKeyAccountLiabilityToAuditRequest,
    AddKeyAccountLiabilityToAuditResponse,
    GetKeyAccountLiabilityRequest,
    GetKeyAccountLiabilityResponse,
    ListKeyAccountLiabilitiesByAuditRequest,
    ListKeyAccountLiabilitiesByAuditResponse,
    ListKeyAccountLiabilitiesNotInAuditRequest,
    ListKeyAccountLiabilitiesNotInAuditResponse,
)
from protobufs.institution.auditGenKeyAccountLiability_pb2_grpc import (
    AuditGenKeyAccountLiabilityServicer,
    add_AuditGenKeyAccountLiabilityServicer_to_server,
)
from sqlalchemy import and_, or_
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.audit import Audit
from backend.sql.audit_key_account_liability import AuditKeyAccountLiability
from backend.sql.audit_user_currency_liability import AuditUserCurrencyLiability
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.key_client import KeyClient
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_KEY_ACCOUNT_LIABILITIES_BY_AUDIT_NEXT_TOKEN_NAME = "ListKeyAccountLiabilitiesByAudit"
LIST_KEY_ACCOUNT_LIABILITIES_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListKeyAccountLiabilitiesNotInAudit"


class ListKeyAccountLiabilitiesByAudit(
    ListRPC[
        ListKeyAccountLiabilitiesByAuditRequest,
        ListKeyAccountLiabilitiesByAuditResponse,
        ListKeyAccountLiabilitiesByAuditRequest.Request,
        ListKeyAccountLiabilitiesByAuditResponse.Response,
    ]
):
    def __init__(
        self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker, blockchain_client: BlockchainClient
    ):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker
        self._blockchain_client = blockchain_client

    next_token_name = LIST_KEY_ACCOUNT_LIABILITIES_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeyAccountLiabilitiesByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyAccountLiabilitiesByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountLiabilitiesByAuditResponse.Response]:
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
        request: ListKeyAccountLiabilitiesByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountLiabilitiesByAuditResponse.Response]:
        with self._sessionmaker() as session:
            key_account_liabilities = (
                session.query(AuditKeyAccountLiability)
                .filter(
                    AuditKeyAccountLiability.audit_version == request.auditVersion,
                    AuditKeyAccountLiability.created_at <= initial_request_timestamp,
                )
                .order_by(AuditKeyAccountLiability.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )

            responses: List[ListKeyAccountLiabilitiesByAuditResponse.Response] = []
            for key_account_liability in key_account_liabilities:
                responses.append(
                    ListKeyAccountLiabilitiesByAuditResponse.Response(
                        keyAccountLiability=KeyAccountLiability(
                            keyId=key_account_liability.key_uuid.bytes,
                            accountId=key_account_liability.account_uuid.bytes,
                            p=key_account_liability.p.export(),
                            nizk=key_account_liability.nizk.serialize(),
                            auditVersion=request.auditVersion,
                        )
                    )
                )
        return responses


class ListKeyAccountLiabilitiesNotInAudit(
    ListRPC[
        ListKeyAccountLiabilitiesNotInAuditRequest,
        ListKeyAccountLiabilitiesNotInAuditResponse,
        ListKeyAccountLiabilitiesNotInAuditRequest.Request,
        ListKeyAccountLiabilitiesNotInAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_KEY_ACCOUNT_LIABILITIES_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListKeyAccountLiabilitiesNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyAccountLiabilitiesNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountLiabilitiesNotInAuditResponse.Response]:
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
        request: ListKeyAccountLiabilitiesNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListKeyAccountLiabilitiesNotInAuditResponse.Response]:
        response: List[ListKeyAccountLiabilitiesNotInAuditResponse.Response] = []
        with self._sessionmaker() as session:
            audit = session.query(Audit).filter(Audit.version_number == request.auditVersion).one()

            missing_key_account_commitments = (
                session.query(KeyAccountCommitment)
                .filter(
                    Account.uuid == KeyAccountCommitment.account_uuid,
                    KeyAccountCommitment.created_at < initial_request_timestamp,
                    or_(
                        *[
                            and_(
                                Account.currency == currency,
                                KeyAccountCommitment.block_number < audit.get_block(CURRENCY_TO_BLOCKCHAIN[currency]),
                            )
                            for currency in Currency
                        ]
                    ),
                )
                .order_by(KeyAccountCommitment.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            for kac in missing_key_account_commitments:
                response.append(
                    ListKeyAccountLiabilitiesNotInAuditResponse.Response(
                        keyId=kac.key_uuid.bytes,
                        accountId=kac.account_uuid.bytes,
                    )
                )
        return response


class AuditGenKeyAccountLiabilityService(AuditGenKeyAccountLiabilityServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
        blockchain_client: BlockchainClient,
        key_client: KeyClient,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        add_AuditGenKeyAccountLiabilityServicer_to_server(self, server)
        self._blockchain_client = blockchain_client
        self._key_client = key_client
        self._jwt_client = jwt_client
        self._list_key_account_liabilities_by_audit = ListKeyAccountLiabilitiesByAudit(
            jwt_client, sessionmaker, blockchain_client
        )
        self._list_key_account_liabilities_not_in_audit = ListKeyAccountLiabilitiesNotInAudit(jwt_client, sessionmaker)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListKeyAccountLiabilitiesByAudit(
        self, request: ListKeyAccountLiabilitiesByAuditRequest, context: grpc.ServicerContext
    ) -> ListKeyAccountLiabilitiesByAuditResponse:
        return self._list_key_account_liabilities_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def ListKeyAccountLiabilitiesNotInAudit(
        self, request: ListKeyAccountLiabilitiesNotInAuditRequest, context: grpc.ServicerContext
    ) -> ListKeyAccountLiabilitiesNotInAuditResponse:
        return self._list_key_account_liabilities_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddKeyAccountLiabilityToAudit(
        self, request: AddKeyAccountLiabilityToAuditRequest, context: grpc.ServicerContext
    ) -> AddKeyAccountLiabilityToAuditResponse:
        key_uuid = bytes_to_uuid(request.keyId)
        account_uuid = bytes_to_uuid(request.accountId)
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            # not locking as we are only reading in this session
            audit = session.query(Audit).filter(Audit.version_number == audit_version).one()
            key_account_commitment, key, account = (
                session.query(KeyAccountCommitment, Key, Account)
                .filter(
                    KeyAccountCommitment.account_uuid == account_uuid,
                    KeyAccountCommitment.key_uuid == key_uuid,
                    KeyAccountCommitment.account_uuid == Account.uuid,
                    Key.key_uuid == KeyAccountCommitment.key_uuid,
                    or_(
                        *[
                            and_(
                                Account.currency == currency,
                                KeyAccountCommitment.block_number < audit.get_block(CURRENCY_TO_BLOCKCHAIN[currency]),
                            )
                            for currency in Currency
                        ]
                    ),
                )
                .one()
            )
            if key.audit_publish_version is None or key.audit_publish_version > request.auditVersion:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"key {key.key_uuid} not yet added to audit")
                raise ValueError(f"key {key.key_uuid} not yet added to audit")
            if account.audit_version is None or account.audit_version > request.auditVersion:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"account {account.uuid} not yet added to audit")
                raise ValueError(f"account {account.uuid} not yet added to audit")
            if (
                key_account_commitment.audit_publish_version is None
                or key_account_commitment.audit_publish_version > request.auditVersion
            ):
                context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION,
                    f"key_account_commitment {key_account_commitment.uuid} not yet added to audit",
                )
                raise ValueError(f"key_account_commitment {key_account_commitment.uuid} not yet added to audit")
            currency = account.currency
            from_block_number = key_account_commitment.block_number + 1  # commitment is valid after this block!
            to_block_number = audit.get_block(CURRENCY_TO_BLOCKCHAIN[currency])
            if from_block_number > to_block_number:
                message = (
                    f"(key account commitment block_number + 1 =({from_block_number}))"
                    f" > audit block number({to_block_number})"
                )
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, message)
                raise ValueError(message)

            x = key.permuted_private_key
            y = key.permuted_secp256k1_public_key
            s = Bn(key_account_commitment.s)
            x_hat = s if s == Bn(0) else s * x
            t = key_account_commitment.r

        cumulative_deposit_amount = self._blockchain_client.get_cumulative_deposits(
            key_uuid, currency, from_block_number, to_block_number
        )
        amount = Bn.from_decimal(str(int(cumulative_deposit_amount * CURRENCY_PRECISIONS[currency])))
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
                AuditKeyAccountLiability(
                    audit_version=audit_version,
                    key_uuid=key_uuid,
                    account_uuid=account_uuid,
                    p=p,
                    v=v,
                    nizk=nizk,
                )
            )
            user_currency_liability = (
                session.query(AuditUserCurrencyLiability)
                .filter(
                    AuditUserCurrencyLiability.audit_version == audit_version,
                    AuditUserCurrencyLiability.user_uuid == account.user_uuid,
                    AuditUserCurrencyLiability.currency == currency,
                )
                .populate_existing()
                .with_for_update()
                .one_or_none()
            )
            if user_currency_liability is None:
                previous_audit_user_currency_liability = (
                    session.query(AuditUserCurrencyLiability)
                    .filter(
                        AuditUserCurrencyLiability.audit_version == request.auditVersion - 1,
                        AuditUserCurrencyLiability.user_uuid == account.user_uuid,
                        AuditUserCurrencyLiability.currency == account.currency,
                    )
                    .one_or_none()
                )
                if previous_audit_user_currency_liability is None:
                    cumulative_account_delta_amount = Bn(0)
                    cumulative_account_delta_v = Bn(0)
                else:
                    cumulative_account_delta_amount = (
                        previous_audit_user_currency_liability.cumulative_account_delta_amount
                    )
                    cumulative_account_delta_v = previous_audit_user_currency_liability.cumulative_account_delta_v
                user_currency_liability = AuditUserCurrencyLiability(
                    audit_version=request.auditVersion,
                    user_uuid=account.user_uuid,
                    currency=account.currency,
                    cumulative_account_delta_amount=cumulative_account_delta_amount,
                    cumulative_account_delta_v=cumulative_account_delta_v,
                )
                session.add(user_currency_liability)
                session.flush()  # populate defaults
            new_cum_deposit_amount = user_currency_liability.cumulative_deposit_amount + s * amount
            new_cum_deposit_v = (user_currency_liability.cumulative_deposit_v + v) % SECP256K1_ORDER

            assert user_currency_liability.to_currency_amount is None
            assert user_currency_liability.to_currency_nizk is None

            user_currency_liability.cumulative_deposit_amount = new_cum_deposit_amount
            user_currency_liability.cumulative_deposit_v = new_cum_deposit_v
            session.commit()
        return AddKeyAccountLiabilityToAuditResponse(
            keyAccountLiability=KeyAccountLiability(
                keyId=key_uuid.bytes,
                accountId=account_uuid.bytes,
                p=p.export(),
                nizk=nizk.serialize(),
                auditVersion=audit_version,
            )
        )

    @admin_authenticated
    def GetKeyAccountLiability(
        self, request: GetKeyAccountLiabilityRequest, context: grpc.ServicerContext
    ) -> GetKeyAccountLiabilityResponse:
        key_uuid = bytes_to_uuid(request.keyId)
        account_uuid = bytes_to_uuid(request.accountId)
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            key_account_liability = (
                session.query(AuditKeyAccountLiability)
                .filter(
                    AuditKeyAccountLiability.audit_version == audit_version,
                    AuditKeyAccountLiability.key_uuid == key_uuid,
                    AuditKeyAccountLiability.account_uuid == account_uuid,
                )
                .one()
            )
            return GetKeyAccountLiabilityResponse(
                keyAccountLiability=KeyAccountLiability(
                    keyId=key_uuid.bytes,
                    accountId=account_uuid.bytes,
                    p=key_account_liability.p.export(),
                    nizk=key_account_liability.nizk.serialize(),
                    auditVersion=audit_version,
                )
            )
