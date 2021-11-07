import logging
import uuid
from datetime import datetime
from fractions import Fraction
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import (
    ADMIN_UUID,
    AUDIT_BASE_CURRENCY,
    PAGINATION_LIMIT,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
    Blockchain,
    Currency,
)
from common.utils.datetime import datetime_to_protobuf, protobuf_to_datetime
from common.utils.zk.currency_conversion import generate_currency_conversion_commitment
from common.utils.zk.less_than_equal import generate_lte_commitment
from petlib.bn import Bn
from protobufs.audit_pb2 import Audit as AuditPB2
from protobufs.audit_pb2 import (
    CurrencyConversion,
    ExchangeRate,
    ExchangeRates,
    SolvencyProof,
)
from protobufs.institution.auditGen_pb2 import (
    FinalizeAuditRequest,
    FinalizeAuditResponse,
    GenerateAuditRequest,
    GenerateAuditResponse,
    GetAuditRequest,
    GetAuditResponse,
    ListAuditsRequest,
    ListAuditsResponse,
)
from protobufs.institution.auditGen_pb2_grpc import (
    AuditGenServicer,
    add_AuditGenServicer_to_server,
)
from sqlalchemy import desc

from backend.sql.audit import Audit
from backend.sql.audit_currency_asset import AuditCurrencyAsset
from backend.sql.audit_user_cumulative_liability import AuditUserCumulativeLiability
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.list_rpc import ListRPC
from backend.utils.marketdata_client import MarketdataClient

LOGGER = logging.getLogger(__name__)

LIST_AUDITS_NEXT_TOKEN_NAME = "ListAudits"


class ListAudits(
    ListRPC[
        ListAuditsRequest,
        ListAuditsResponse,
        ListAuditsRequest.Request,
        ListAuditsResponse.Response,
    ]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_AUDITS_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListAuditsResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAuditsRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAuditsResponse.Response]:
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
        request: ListAuditsRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAuditsResponse.Response]:
        from_timestamp = protobuf_to_datetime(request.fromTimestamp)
        to_timestamp = protobuf_to_datetime(request.toTimestamp)
        if from_timestamp > to_timestamp:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "fromTimestamp > toTimestamp")
            raise ValueError("fromTimestamp > toTimestamp")
        if to_timestamp > initial_request_timestamp:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "to_timestamp > current time")
            raise ValueError("to_timestamp > current time")

        with self._sessionmaker() as session:
            audits = (
                session.query(Audit)
                .filter(Audit.timestamp >= from_timestamp, Audit.timestamp <= to_timestamp)
                .order_by(desc(Audit.timestamp))
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )
            audit_metadata_list: List[ListAuditsResponse.Response] = []
            for audit in audits:
                audit_metadata_list.append(
                    ListAuditsResponse.Response(
                        audit=AuditPB2(
                            bitcoinBlock=audit.bitcoin_block,
                            ethereumBlock=audit.ethereum_block,
                            timestamp=datetime_to_protobuf(audit.timestamp),
                            baseCurrency=audit.base_currency,
                            exchangeRates=audit.exchange_rates,
                        ),
                        solvencyProof=audit.solvency_proof,
                    )
                )
        return audit_metadata_list


class AuditGenService(AuditGenServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
        blockchain_client: BlockchainClient,
        marketdata_client: MarketdataClient,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._jwt_client = jwt_client
        add_AuditGenServicer_to_server(self, server)
        self._blockchain_client = blockchain_client
        self._list_audits = ListAudits(jwt_client, sessionmaker)
        self._marketdata_client = marketdata_client

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def GenerateAudit(
        self,
        request: GenerateAuditRequest,
        context: grpc.ServicerContext,
    ) -> GenerateAuditResponse:
        with self._sessionmaker() as session:
            row_count = session.query(Audit).filter(Audit.finalized.is_(False)).count()
            if row_count > 0:
                assert row_count == 1
                context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION,
                    "Please finalize the existing audit before creating a new one",
                )
                raise RuntimeError("Please finalize the existing audit before creating a new one")
        audit_timestamp = self._blockchain_client.get_latest_processed_block_timestamp_across_all_blockchains()
        bitcoin_block_number = self._blockchain_client.get_block_number_at_or_after_timestamp(
            Blockchain.BTC, audit_timestamp
        )
        ethereum_block_number = self._blockchain_client.get_block_number_at_or_after_timestamp(
            Blockchain.ETH, audit_timestamp
        )
        LOGGER.info(
            "Creating audit with timestamp %s, bitcoin block %d, ethereum block %d",
            audit_timestamp,
            bitcoin_block_number,
            ethereum_block_number,
        )
        exchange_rates: List[ExchangeRate] = []
        for currency in Currency:
            price, ignored_timestamp = self._marketdata_client.get_latest_quote(
                sell_currency=currency, buy_currency=AUDIT_BASE_CURRENCY
            )
            exchange_rates.append(
                ExchangeRate(
                    currency=currency.name,
                    rate=str(price.normalize()),
                )
            )
        with self._sessionmaker() as session:
            audit = Audit(
                bitcoin_block=bitcoin_block_number,
                ethereum_block=ethereum_block_number,
                timestamp=audit_timestamp,
                base_currency=AUDIT_BASE_CURRENCY,
                exchange_rates=ExchangeRates(exchangeRates=exchange_rates),
            )
            session.add(audit)
            session.flush()  # generate an audit number by manually flushing
            for currency in Currency:
                session.add(
                    AuditCurrencyAsset(
                        audit_version=audit.version_number,
                        currency=currency,
                    )
                )
            session.commit()
            created_at = audit.timestamp
            version_number = audit.version_number
        return GenerateAuditResponse(
            audit=AuditPB2(
                bitcoinBlock=bitcoin_block_number,
                ethereumBlock=ethereum_block_number,
                timestamp=datetime_to_protobuf(created_at),
                baseCurrency=AUDIT_BASE_CURRENCY.name,
                exchangeRates=ExchangeRates(exchangeRates=exchange_rates),
                auditVersion=version_number,
            ),
        )

    @admin_authenticated
    def ListAudits(
        self,
        request: ListAuditsRequest,
        context: grpc.ServicerContext,
    ) -> ListAuditsResponse:
        return self._list_audits(request, context, ADMIN_UUID)

    @admin_authenticated
    def GetAudit(
        self,
        request: GetAuditRequest,
        context: grpc.ServicerContext,
    ) -> GetAuditResponse:
        with self._sessionmaker() as session:
            audit = session.query(Audit).filter(Audit.version_number == request.auditVersion).one()
            return GetAuditResponse(
                audit=AuditPB2(
                    bitcoinBlock=audit.bitcoin_block,
                    ethereumBlock=audit.ethereum_block,
                    timestamp=datetime_to_protobuf(audit.timestamp),
                    baseCurrency=audit.base_currency,
                    exchangeRates=audit.exchange_rates,
                    auditVersion=audit.version_number,
                ),
                solvencyProof=audit.solvency_proof,
            )

    @admin_authenticated
    def FinalizeAudit(
        self,
        request: FinalizeAuditRequest,
        context: grpc.ServicerContext,
    ) -> FinalizeAuditResponse:
        with self._sessionmaker() as session:
            audit = (
                session.query(Audit)
                .filter(Audit.version_number == request.auditVersion, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update()
                .one()
            )
            base_currency = audit.base_currency
            exchange_rates = audit.exchange_rates
            currency_to_exchange_rate = {
                Currency[exchange_rate.currency]: Fraction(exchange_rate.rate)
                for exchange_rate in exchange_rates.exchangeRates
            }

            audit_currency_assets = (
                session.query(AuditCurrencyAsset)
                .filter(
                    AuditCurrencyAsset.audit_version == request.auditVersion,
                )
                .populate_existing()
                .with_for_update()
                .all()
            )
            asset_currency_conversions: List[CurrencyConversion] = []
            cumulative_asset_amount = Bn(0)
            cumulative_asset_random = Bn(0)
            for audit_currency_asset in audit_currency_assets:
                currency = audit_currency_asset.currency
                cumulative_assets = audit_currency_asset.cumulative_assets
                cumulative_v = audit_currency_asset.cumulative_v
                to_currency_random = audit_currency_asset.to_currency_v
                cumulative_asset_random += to_currency_random
                cumulative_asset_random %= SECP256K1_ORDER
                to_currency_amount, nizk = generate_currency_conversion_commitment(
                    from_currency_value=cumulative_assets,
                    from_currency_random=cumulative_v,
                    to_currency_random=to_currency_random,
                    from_currency=currency,
                    to_currency=base_currency,
                    exchange_rate=currency_to_exchange_rate[currency],
                )
                cumulative_asset_amount += to_currency_amount
                assert audit_currency_asset.to_currency_amount is None
                assert audit_currency_asset.to_currency_nizk is None
                audit_currency_asset.to_currency_amount = to_currency_amount
                audit_currency_asset.to_currency_nizk = nizk
                asset_currency_conversions.append(
                    CurrencyConversion(
                        fromCurrency=currency.name,
                        toCurrency=base_currency.name,
                        fromCurrencyCommitment=(
                            cumulative_assets * SECP256K1_GENERATOR + cumulative_v * SECP256K1_ALTERNATIVE_GENERATOR
                        ).export(),
                        toCurrencyCommitment=(
                            to_currency_amount * SECP256K1_GENERATOR
                            + to_currency_random * SECP256K1_ALTERNATIVE_GENERATOR
                        ).export(),
                        nizk=nizk.serialize(),
                        auditVersion=request.auditVersion,
                    )
                )

            cumulative_liability_amount = Bn(0)
            cumulative_liability_random = Bn(0)
            user_cumulative_liabilities = (
                session.query(AuditUserCumulativeLiability)
                .filter(
                    AuditUserCumulativeLiability.audit_version == audit.version_number,
                )
                .all()
            )
            for user_cumulative_liability in user_cumulative_liabilities:
                if user_cumulative_liability.cumulative_to_currency_amount < 0:
                    # users with overall negative balances don't decrease the overall liabilities
                    continue
                cumulative_liability_amount += user_cumulative_liability.cumulative_to_currency_amount
                cumulative_liability_random = (
                    cumulative_liability_random + user_cumulative_liability.cumulative_to_currency_v
                ) % SECP256K1_ORDER

            solvency_nizk = generate_lte_commitment(
                lhs_amount=cumulative_liability_amount,
                lhs_random=cumulative_liability_random,
                rhs_amount=cumulative_asset_amount,
                rhs_random=cumulative_asset_random,
            )

            solvency_proof = SolvencyProof(
                assetCurrencyConversions=asset_currency_conversions,
                nizk=solvency_nizk.serialize(),
                auditVersion=request.auditVersion,
            )
            assert audit.cumulative_asset_amount is None
            assert audit.cumulative_asset_random is None
            assert audit.cumulative_liability_amount is None
            assert audit.cumulative_liability_random is None
            assert audit.finalized is False

            audit.cumulative_asset_amount = cumulative_asset_amount
            audit.cumulative_asset_random = cumulative_asset_random
            audit.cumulative_liability_amount = cumulative_liability_amount
            audit.cumulative_liability_random = cumulative_liability_random
            audit.solvency_proof = solvency_proof
            audit.finalized = True

            session.commit()
            return FinalizeAuditResponse(
                audit=AuditPB2(
                    bitcoinBlock=audit.bitcoin_block,
                    ethereumBlock=audit.ethereum_block,
                    timestamp=datetime_to_protobuf(audit.timestamp),
                    baseCurrency=audit.base_currency.name,
                    exchangeRates=audit.exchange_rates,
                    auditVersion=audit.version_number,
                ),
                solvencyProof=solvency_proof,
            )
