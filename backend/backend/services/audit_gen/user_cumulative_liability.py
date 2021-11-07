import logging
import uuid
from datetime import datetime
from fractions import Fraction
from typing import Dict, List, Sequence, Tuple

import grpc
import sqlalchemy.orm
from common.constants import (
    ADMIN_UUID,
    MAX_USER_BAL,
    MAX_USER_BAL_BITS,
    PAGINATION_LIMIT,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
    Currency,
)
from common.utils.uuid import bytes_to_uuid
from common.utils.zk.currency_conversion import generate_currency_conversion_commitment
from common.utils.zk.power_two import generate_power_two_commitment
from petlib.bn import Bn
from protobufs.audit_pb2 import CurrencyConversion, UserCumulativeLiability
from protobufs.institution.auditGenUserCumulativeLiability_pb2 import (
    AddUserCumulativeLiabilityToAuditRequest,
    AddUserCumulativeLiabilityToAuditResponse,
    GetUserCumulativeLiabilityRequest,
    GetUserCumulativeLiabilityResponse,
    ListUserCumulativeLiabilitiesByAuditRequest,
    ListUserCumulativeLiabilitiesByAuditResponse,
    ListUserCumulativeLiabilitiesNotInAuditRequest,
    ListUserCumulativeLiabilitiesNotInAuditResponse,
)
from protobufs.institution.auditGenUserCumulativeLiability_pb2_grpc import (
    AuditGenUserCumulativeLiabilityServicer,
    add_AuditGenUserCumulativeLiabilityServicer_to_server,
)
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.audit import Audit
from backend.sql.audit_user_cumulative_liability import AuditUserCumulativeLiability
from backend.sql.audit_user_currency_liability import AuditUserCurrencyLiability
from backend.sql.user import User
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.key_client import KeyClient
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_USER_CUMULATIVE_LIABILITIES_BY_AUDIT_NEXT_TOKEN_NAME = "ListUserCumulativeLiabilitiesByAudit"
LIST_USER_CUMULATIVE_LIABILITIES_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListUserCumulativeLiabilitiesNotInAudit"


class ListUserCumulativeLiabilitiesByAudit(
    ListRPC[
        ListUserCumulativeLiabilitiesByAuditRequest,
        ListUserCumulativeLiabilitiesByAuditResponse,
        ListUserCumulativeLiabilitiesByAuditRequest.Request,
        ListUserCumulativeLiabilitiesByAuditResponse.Response,
    ]
):
    def __init__(
        self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker, blockchain_client: BlockchainClient
    ):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker
        self._blockchain_client = blockchain_client

    next_token_name = LIST_USER_CUMULATIVE_LIABILITIES_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListUserCumulativeLiabilitiesByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListUserCumulativeLiabilitiesByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserCumulativeLiabilitiesByAuditResponse.Response]:
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            try:
                session.query(Audit).filter(Audit.version_number == audit_version, Audit.finalized.is_(True)).one()
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
        request: ListUserCumulativeLiabilitiesByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserCumulativeLiabilitiesByAuditResponse.Response]:
        with self._sessionmaker() as session:
            audit = session.query(Audit).filter(Audit.version_number == request.auditVersion).one()
            user_cumulative_liabilities = (
                session.query(AuditUserCumulativeLiability)
                .filter(
                    AuditUserCumulativeLiability.audit_version == request.auditVersion,
                    AuditUserCumulativeLiability.created_at <= initial_request_timestamp,
                )
                .order_by(AuditUserCumulativeLiability.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            user_currency_liabilities = (
                session.query(AuditUserCurrencyLiability)
                .filter(
                    AuditUserCurrencyLiability.audit_version == request.auditVersion,
                    AuditUserCurrencyLiability.user_uuid.in_([ucl.user_uuid for ucl in user_cumulative_liabilities]),
                )
                .all()
            )
            user_uuid_to_user_currency_liabilities: Dict[uuid.UUID, List[AuditUserCurrencyLiability]] = {}
            for user_currency_liability in user_currency_liabilities:
                if user_currency_liability.user_uuid not in user_uuid_to_user_currency_liabilities:
                    user_uuid_to_user_currency_liabilities[user_currency_liability.user_uuid] = []
                user_uuid_to_user_currency_liabilities[user_currency_liability.user_uuid].append(
                    user_currency_liability
                )

            responses: List[ListUserCumulativeLiabilitiesByAuditResponse.Response] = []
            for user_cumulative_liability in user_cumulative_liabilities:
                currency_conversions: List[CurrencyConversion] = []
                for user_currency_liability in user_uuid_to_user_currency_liabilities[
                    user_cumulative_liability.user_uuid
                ]:
                    from_currency_commitment = (
                        user_currency_liability.cumulative_deposit_amount
                        + user_currency_liability.cumulative_account_delta_amount
                    ) * SECP256K1_GENERATOR + (
                        user_currency_liability.cumulative_deposit_v
                        + user_currency_liability.cumulative_account_delta_v
                    ) * SECP256K1_ALTERNATIVE_GENERATOR
                    to_currency_commitment = (
                        user_currency_liability.to_currency_amount * SECP256K1_GENERATOR
                        + user_currency_liability.to_currency_v * SECP256K1_ALTERNATIVE_GENERATOR
                    )
                    currency_conversions.append(
                        CurrencyConversion(
                            fromCurrency=user_currency_liability.currency.name,
                            toCurrency=audit.baseCurrency,
                            fromCurrencyCommitment=from_currency_commitment.export(),
                            toCurrencyCommitment=to_currency_commitment.export(),
                            nizk=user_currency_liability.to_currency_nizk,
                            auditVersion=request.auditVersion,
                        )
                    )
                responses.append(
                    ListUserCumulativeLiabilitiesByAuditResponse.Response(
                        userCumulativeLiability=UserCumulativeLiability(
                            userId=user_cumulative_liability.key_uuid.bytes,
                            liabilityCurrencyConversions=currency_conversions,
                            isNegative=user_cumulative_liability.cumulative_to_currency_amount < Bn(0),
                            nizk=user_cumulative_liability.nizk,
                            auditVersion=request.auditVersion,
                        )
                    )
                )
        return responses


class ListUserCumulativeLiabilitiesNotInAudit(
    ListRPC[
        ListUserCumulativeLiabilitiesNotInAuditRequest,
        ListUserCumulativeLiabilitiesNotInAuditResponse,
        ListUserCumulativeLiabilitiesNotInAuditRequest.Request,
        ListUserCumulativeLiabilitiesNotInAuditResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_USER_CUMULATIVE_LIABILITIES_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListUserCumulativeLiabilitiesNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListUserCumulativeLiabilitiesNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserCumulativeLiabilitiesNotInAuditResponse.Response]:
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
        request: ListUserCumulativeLiabilitiesNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListUserCumulativeLiabilitiesNotInAuditResponse.Response]:
        response: List[ListUserCumulativeLiabilitiesNotInAuditResponse.Response] = []
        with self._sessionmaker() as session:
            ignored_audit = session.query(Audit).filter(Audit.version_number == request.auditVersion).one()

            user_uuids: Sequence[Tuple[uuid.UUID]] = (
                session.query(User.user_uuid)
                .filter(User.created_at < initial_request_timestamp)
                .order_by(User.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            for (user_uuid_to_audit,) in user_uuids:
                response.append(
                    ListUserCumulativeLiabilitiesNotInAuditResponse.Response(
                        userId=user_uuid_to_audit.bytes,
                    )
                )
        return response


class AuditGenUserCumulativeLiabilityService(AuditGenUserCumulativeLiabilityServicer, AuthenticatedServicer):
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
        add_AuditGenUserCumulativeLiabilityServicer_to_server(self, server)
        self._blockchain_client = blockchain_client
        self._key_client = key_client
        self._jwt_client = jwt_client
        self._list_user_cumulative_liabilities_by_audit = ListUserCumulativeLiabilitiesByAudit(
            jwt_client, sessionmaker, blockchain_client
        )
        self._list_user_cumulative_liabilities_not_in_audit = ListUserCumulativeLiabilitiesNotInAudit(
            jwt_client, sessionmaker
        )

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListUserCumulativeLiabilitiesByAudit(
        self, request: ListUserCumulativeLiabilitiesByAuditRequest, context: grpc.ServicerContext
    ) -> ListUserCumulativeLiabilitiesByAuditResponse:
        return self._list_user_cumulative_liabilities_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def ListUserCumulativeLiabilitiesNotInAudit(
        self, request: ListUserCumulativeLiabilitiesNotInAuditRequest, context: grpc.ServicerContext
    ) -> ListUserCumulativeLiabilitiesNotInAuditResponse:
        return self._list_user_cumulative_liabilities_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddUserCumulativeLiabilityToAudit(
        self, request: AddUserCumulativeLiabilityToAuditRequest, context: grpc.ServicerContext
    ) -> AddUserCumulativeLiabilityToAuditResponse:
        user_uuid = bytes_to_uuid(request.userId)
        audit_version = request.auditVersion
        LOGGER.info("Processing user cum liability for user %s", user_uuid)
        with self._sessionmaker() as session:
            audit = (
                session.query(Audit)
                .filter(Audit.version_number == audit_version, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update(read=True)
                .one()
            )
            base_currency = audit.base_currency
            exchange_rates = audit.exchange_rates
            currency_to_exchange_rate = {
                Currency[exchange_rate.currency]: Fraction(exchange_rate.rate)
                for exchange_rate in exchange_rates.exchangeRates
            }
            user_currency_liabilities = (
                session.query(AuditUserCurrencyLiability)
                .filter(
                    AuditUserCurrencyLiability.audit_version == audit_version,
                    AuditUserCurrencyLiability.user_uuid == user_uuid,
                )
                .populate_existing()
                .with_for_update()
                .all()
            )
            cumulative_liability_amount = Bn(0)
            cumulative_liability_random = Bn(0)
            liability_currency_conversions: List[CurrencyConversion] = []
            LOGGER.info("Fetched currencies for  user cum liability for user %s", user_uuid)
            for user_currency_liability in user_currency_liabilities:
                currency = user_currency_liability.currency
                cumulative_liabilities = (
                    user_currency_liability.cumulative_deposit_amount
                    + user_currency_liability.cumulative_account_delta_amount
                )
                cumulative_v = (
                    user_currency_liability.cumulative_deposit_v + user_currency_liability.cumulative_account_delta_v
                )
                to_currency_random = user_currency_liability.to_currency_v
                cumulative_liability_random += to_currency_random
                cumulative_liability_random %= SECP256K1_ORDER
                to_currency_amount, nizk = generate_currency_conversion_commitment(
                    from_currency_value=cumulative_liabilities,
                    from_currency_random=cumulative_v,
                    to_currency_random=to_currency_random,
                    from_currency=currency,
                    to_currency=base_currency,
                    exchange_rate=currency_to_exchange_rate[currency],
                )
                cumulative_liability_amount += to_currency_amount
                assert user_currency_liability.to_currency_amount is None
                assert user_currency_liability.to_currency_nizk is None
                user_currency_liability.to_currency_amount = to_currency_amount
                user_currency_liability.to_currency_nizk = nizk
                liability_currency_conversions.append(
                    CurrencyConversion(
                        fromCurrency=currency.name,
                        toCurrency=base_currency.name,
                        fromCurrencyCommitment=(
                            cumulative_liabilities * SECP256K1_GENERATOR
                            + cumulative_v * SECP256K1_ALTERNATIVE_GENERATOR
                        ).export(),
                        toCurrencyCommitment=(
                            to_currency_amount * SECP256K1_GENERATOR
                            + to_currency_random * SECP256K1_ALTERNATIVE_GENERATOR
                        ).export(),
                        nizk=nizk.serialize(),
                        auditVersion=request.auditVersion,
                    )
                )
            LOGGER.info("Fetched currencies for  user cum liability for user %s", user_uuid)
            is_negative = False
            if cumulative_liability_amount < 0:
                # Prove that the user is insolvent
                LOGGER.warning("User %s is insolvent with balance %s", user_uuid, cumulative_liability_amount)
                is_negative = True
            amount_nizk = generate_power_two_commitment(
                amount=cumulative_liability_amount + (MAX_USER_BAL if is_negative else Bn(0)),
                random=cumulative_liability_random,
                num_bits=MAX_USER_BAL_BITS,
            )

            user_cumulative_liability_pb = UserCumulativeLiability(
                userId=user_uuid.bytes,
                liabilityCurrencyConversions=liability_currency_conversions,
                nizk=amount_nizk.serialize(),
                isNegative=is_negative,
                auditVersion=request.auditVersion,
            )
            session.add(
                AuditUserCumulativeLiability(
                    audit_version=audit_version,
                    user_uuid=user_uuid,
                    cumulative_to_currency_amount=cumulative_liability_amount,
                    cumulative_to_currency_v=cumulative_liability_random,
                    nizk=amount_nizk,
                )
            )
            session.commit()
        return AddUserCumulativeLiabilityToAuditResponse(userCumulativeLiability=user_cumulative_liability_pb)

    @admin_authenticated
    def GetUserCumulativeLiability(
        self, request: GetUserCumulativeLiabilityRequest, context: grpc.ServicerContext
    ) -> GetUserCumulativeLiabilityResponse:
        user_uuid = bytes_to_uuid(request.userId)
        audit_version = request.auditVersion

        with self._sessionmaker() as session:
            audit = session.query(Audit).filter(Audit.version_number == audit_version).one()
            user_cumulative_liability = (
                session.query(AuditUserCumulativeLiability)
                .filter(
                    AuditUserCumulativeLiability.audit_version == request.auditVersion,
                    AuditUserCumulativeLiability.user_uuid == user_uuid,
                )
                .one()
            )
            user_currency_liabilities = (
                session.query(AuditUserCurrencyLiability)
                .filter(
                    AuditUserCurrencyLiability.audit_version == request.auditVersion,
                    AuditUserCurrencyLiability.user_uuid == user_uuid,
                )
                .all()
            )
            currency_conversions: List[CurrencyConversion] = []
            for user_currency_liability in user_currency_liabilities:
                from_currency_commitment = (
                    user_currency_liability.cumulative_deposit_amount
                    + user_currency_liability.cumulative_account_delta_amount
                ) * SECP256K1_GENERATOR + (
                    user_currency_liability.cumulative_deposit_v + user_currency_liability.cumulative_account_delta_v
                ) * SECP256K1_ALTERNATIVE_GENERATOR
                to_currency_commitment = (
                    user_currency_liability.to_currency_amount * SECP256K1_GENERATOR
                    + user_currency_liability.to_currency_v * SECP256K1_ALTERNATIVE_GENERATOR
                )
                currency_conversions.append(
                    CurrencyConversion(
                        fromCurrency=user_currency_liability.currency.name,
                        toCurrency=audit.baseCurrency,
                        fromCurrencyCommitment=from_currency_commitment.export(),
                        toCurrencyCommitment=to_currency_commitment.export(),
                        nizk=user_currency_liability.to_currency_nizk,
                        auditVersion=request.auditVersion,
                    )
                )
            return GetUserCumulativeLiabilityResponse(
                userCumulativeLiability=UserCumulativeLiability(
                    userId=user_cumulative_liability.key_uuid.bytes,
                    liabilityCurrencyConversions=currency_conversions,
                    isNegative=user_cumulative_liability.cumulative_to_currency_amount < Bn(0),
                    nizk=user_cumulative_liability.nizk,
                    auditVersion=request.auditVersion,
                )
            )
