import logging
import uuid
from datetime import datetime
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import ADMIN_UUID, PAGINATION_LIMIT, SECP256K1_ORDER, Blockchain
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid
from petlib.bn import Bn
from protobufs.account_pb2 import AccountDeltaGroupChallengeRequest
from protobufs.audit_pb2 import AccountDeltaGroup as AccountDeltaGroupPB2
from protobufs.institution.account_pb2 import TransactionStatus
from protobufs.institution.auditGenAccountDeltaGroup_pb2 import (
    AddAccountDeltaGroupToAuditRequest,
    AddAccountDeltaGroupToAuditResponse,
    GetAccountDeltaGroupRequest,
    GetAccountDeltaGroupResponse,
    ListAccountDeltaGroupsByAuditRequest,
    ListAccountDeltaGroupsByAuditResponse,
    ListAccountDeltaGroupsNotInAuditRequest,
    ListAccountDeltaGroupsNotInAuditResponse,
)
from protobufs.institution.auditGenAccountDeltaGroup_pb2_grpc import (
    AuditGenAccountDeltaGroupServicer,
    add_AuditGenAccountDeltaGroupServicer_to_server,
)
from sqlalchemy import or_
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.account_delta import AccountDelta
from backend.sql.account_delta_group import AccountDeltaGroup
from backend.sql.account_delta_group_blockchain_transaction import (
    AccountDeltaGroupBlockchainTransaction,
)
from backend.sql.audit import Audit
from backend.sql.audit_user_currency_liability import AuditUserCurrencyLiability
from backend.sql.blockchain_withdrawal import BlockchainWithdrawal
from backend.sql.challenge import Challenge
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    admin_authenticated,
)
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)

LIST_ACCOUNT_DELTA_GROUPS_NOT_IN_AUDIT_NEXT_TOKEN_NAME = "ListAccountDeltaGroupsNotInAudit"
LIST_ACCOUNT_DELTA_GROUPS_BY_AUDIT_NEXT_TOKEN_NAME = "ListAccountDeltaGroupsByAudit"


class ListAccountDeltaGroupsNotInAudit(
    ListRPC[
        ListAccountDeltaGroupsNotInAuditRequest,
        ListAccountDeltaGroupsNotInAuditResponse,
        ListAccountDeltaGroupsNotInAuditRequest.Request,
        ListAccountDeltaGroupsNotInAuditResponse.Response,
    ]
):
    def __init__(
        self, jwt_client: JWTClient, blockchain_client: BlockchainClient, sessionmaker: sqlalchemy.orm.sessionmaker
    ):
        self._jwt_client = jwt_client
        self._blockchain_client = blockchain_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_ACCOUNT_DELTA_GROUPS_NOT_IN_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListAccountDeltaGroupsNotInAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAccountDeltaGroupsNotInAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountDeltaGroupsNotInAuditResponse.Response]:
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
        request: ListAccountDeltaGroupsNotInAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountDeltaGroupsNotInAuditResponse.Response]:
        with self._sessionmaker() as session:
            completed_account_deltas = (
                session.query(AccountDeltaGroup)
                .filter(
                    AccountDeltaGroup.status == TransactionStatus.COMPLETED,
                    or_(  # back-calculate what wasn't in an audit at this timestamp
                        AccountDeltaGroup.add_to_audit_timestamp.is_(None),
                        AccountDeltaGroup.add_to_audit_timestamp > initial_request_timestamp,
                    ),
                    AccountDeltaGroup.created_at <= initial_request_timestamp,
                )
                .order_by(AccountDeltaGroup.created_at)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )

            challenge_requests_list: List[ListAccountDeltaGroupsNotInAuditResponse.Response] = []
            for delta in completed_account_deltas:
                challenge_requests_list.append(
                    ListAccountDeltaGroupsNotInAuditResponse.Response(accountDeltaGroupId=delta.uuid.bytes)
                )
            return challenge_requests_list


class ListAccountDeltaGroupsByAudit(
    ListRPC[
        ListAccountDeltaGroupsByAuditRequest,
        ListAccountDeltaGroupsByAuditResponse,
        ListAccountDeltaGroupsByAuditRequest.Request,
        ListAccountDeltaGroupsByAuditResponse.Response,
    ]
):
    def __init__(
        self, jwt_client: JWTClient, blockchain_client: BlockchainClient, sessionmaker: sqlalchemy.orm.sessionmaker
    ):
        self._jwt_client = jwt_client
        self._blockchain_client = blockchain_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_ACCOUNT_DELTA_GROUPS_BY_AUDIT_NEXT_TOKEN_NAME

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    list_response_type = ListAccountDeltaGroupsByAuditResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListAccountDeltaGroupsByAuditRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountDeltaGroupsByAuditResponse.Response]:
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
        request: ListAccountDeltaGroupsByAuditRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[ListAccountDeltaGroupsByAuditResponse.Response]:
        with self._sessionmaker() as session:
            account_deltas_and_challenges = (
                session.query(AccountDeltaGroup)
                .filter(
                    AccountDeltaGroup.audit_publish_version == request.auditVersion,
                    Challenge.uuid == AccountDeltaGroup.challenge_uuid,
                    AccountDeltaGroup.add_to_audit_timestamp <= initial_request_timestamp,
                )
                .order_by(AccountDeltaGroup.add_to_audit_timestamp)
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )

            responses: List[ListAccountDeltaGroupsByAuditResponse.Response] = []

            for account_delta_group, challenge in account_deltas_and_challenges:
                blockchain_withdrawals = (
                    session.query(BlockchainWithdrawal)
                    .filter(
                        AccountDeltaGroupBlockchainTransaction.account_delta_group_uuid == account_delta_group.uuid,
                        AccountDeltaGroupBlockchainTransaction.blockchain_withdrawal_uuid == BlockchainWithdrawal.uuid,
                    )
                    .all()
                )
                blockchain_and_tx_params_to_txn_hash = {
                    (
                        blockchain_withdrawal.blockchain,
                        blockchain_withdrawal.tx_params.SerializeToString(),
                    ): blockchain_withdrawal.txn_hash
                    for blockchain_withdrawal in blockchain_withdrawals
                }
                adgcr = AccountDeltaGroupChallengeRequest()
                assert challenge.challenge_request.request.Unpack(adgcr), "failed to unpack challenge"
                txn_ids = [
                    blockchain_and_tx_params_to_txn_hash[(Blockchain[tx.blockchain], tx.txParams.SerializeToString())]
                    for tx in adgcr.transactions
                ]
                responses.append(
                    ListAccountDeltaGroupsByAuditResponse.Response(
                        accountDeltaGroup=AccountDeltaGroupPB2(
                            id=account_delta_group.uuid.bytes,
                            userId=account_delta_group.user_uuid.bytes,
                            challengeRequest=challenge.challenge_request,
                            assertion=challenge.authenticator_assertion_response,
                            txnIds=txn_ids,
                            auditVersion=account_delta_group.audit_publish_version,
                        )
                    )
                )
            return responses


class AuditGenAccountDeltaGroupService(AuditGenAccountDeltaGroupServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        server: grpc.Server,
        blockchain_client: BlockchainClient,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._jwt_client = jwt_client
        self._blockchain_client = blockchain_client
        add_AuditGenAccountDeltaGroupServicer_to_server(self, server)
        self._list_account_delta_groups_not_in_audit = ListAccountDeltaGroupsNotInAudit(
            jwt_client, blockchain_client, sessionmaker
        )
        self._list_account_delta_groups_by_audit = ListAccountDeltaGroupsByAudit(
            jwt_client, blockchain_client, sessionmaker
        )

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @admin_authenticated
    def ListAccountDeltaGroupsNotInAudit(
        self,
        request: ListAccountDeltaGroupsNotInAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListAccountDeltaGroupsNotInAuditResponse:
        return self._list_account_delta_groups_not_in_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def AddAccountDeltaGroupToAudit(
        self,
        request: AddAccountDeltaGroupToAuditRequest,
        context: grpc.ServicerContext,
    ) -> AddAccountDeltaGroupToAuditResponse:
        account_delta_group_uuid = bytes_to_uuid(request.accountDeltaGroupId)
        with self._sessionmaker() as session:
            audit = (
                session.query(Audit)
                .filter(Audit.version_number == request.auditVersion, Audit.finalized.is_(False))
                .populate_existing()
                .with_for_update(read=True)  # TODO we want nowait
                .one()
            )

            account_delta_group = (
                session.query(AccountDeltaGroup)
                .filter(
                    AccountDeltaGroup.uuid == account_delta_group_uuid,
                    AccountDeltaGroup.audit_publish_version.is_(None),
                )
                .populate_existing()
                .with_for_update()
                .one()
            )
            challenge = (
                session.query(Challenge)
                .filter(
                    Challenge.uuid == account_delta_group.challenge_uuid,
                )
                .one()
            )

            blockchain_withdrawals = (
                session.query(BlockchainWithdrawal)
                .filter(
                    AccountDeltaGroupBlockchainTransaction.account_delta_group_uuid == account_delta_group.uuid,
                    AccountDeltaGroupBlockchainTransaction.blockchain_withdrawal_uuid == BlockchainWithdrawal.uuid,
                )
                .all()
            )

            for blockchain_withdrawal in blockchain_withdrawals:
                if blockchain_withdrawal.block_number is None:
                    context.abort(grpc.StatusCode.FAILED_PRECONDITION, "account delta group not completed")
                    raise ValueError("account delta group not completed")

                if blockchain_withdrawal.blockchain == Blockchain.BTC:
                    num_confirmations = (
                        audit.bitcoin_block - blockchain_withdrawal.block_number + 1
                    )  # adding 1 since it's inclusive
                elif blockchain_withdrawal.blockchain == Blockchain.ETH:
                    num_confirmations = (
                        audit.ethereum_block - blockchain_withdrawal.block_number + 1
                    )  # adding 1 since it's inclusive
                else:
                    context.abort(grpc.StatusCode.INTERNAL, "invalid blockchain")
                    raise ValueError("invalid blockchain")

                if num_confirmations < self._blockchain_client.get_num_confirmations(blockchain_withdrawal.blockchain):
                    context.abort(grpc.StatusCode.FAILED_PRECONDITION, "account delta group not completed")
                    raise ValueError("account delta group not completed")

            blockchain_and_tx_params_to_txn_hash = {
                (
                    blockchain_withdrawal.blockchain,
                    blockchain_withdrawal.tx_params.SerializeToString(),
                ): blockchain_withdrawal.txn_hash
                for blockchain_withdrawal in blockchain_withdrawals
            }
            adgcr = AccountDeltaGroupChallengeRequest()
            assert challenge.challenge_request.request.Unpack(adgcr), "failed to unpack challenge"
            txn_ids = [
                blockchain_and_tx_params_to_txn_hash[(Blockchain[tx.blockchain], tx.txParams.SerializeToString())]
                for tx in adgcr.transactions
            ]
            account_delta_group.audit_publish_version = request.auditVersion
            account_delta_group.add_to_audit_timestamp = get_current_datetime()
            account_delta_and_accounts = (
                session.query(AccountDelta, Account)
                .filter(
                    AccountDelta.account_delta_group_uuid == account_delta_group_uuid,
                    AccountDelta.account_uuid == Account.uuid,
                )
                .all()
            )
            currencies = [account.currency for ignored_account_delta, account in account_delta_and_accounts]

            audit_user_currency_liabilities = (  # selecting them all at once to avoid deadlock
                session.query(AuditUserCurrencyLiability)
                .filter(
                    AuditUserCurrencyLiability.audit_version == request.auditVersion,
                    AuditUserCurrencyLiability.user_uuid == account_delta_group.user_uuid,
                    AuditUserCurrencyLiability.currency.in_(currencies),
                )
                .populate_existing()
                .with_for_update()
                .all()
            )

            currency_to_liability = {
                audit_user_currency_liability.currency: audit_user_currency_liability
                for audit_user_currency_liability in audit_user_currency_liabilities
            }
            for account_delta, account in account_delta_and_accounts:
                if account.audit_version is None or account.audit_version > request.auditVersion:
                    context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"account {account.uuid} not yet added to audit")
                    raise ValueError(f"account {account.uuid} not yet added to audit")
                if not account.currency in currency_to_liability:
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
                            previous_audit_user_currency_liability.previous_audit_user_currency_liability
                        )
                        cumulative_account_delta_v = previous_audit_user_currency_liability.cumulative_account_delta_v
                    audit_user_currency_liability = AuditUserCurrencyLiability(
                        audit_version=request.auditVersion,
                        user_uuid=account.user_uuid,
                        currency=account.currency,
                        cumulative_account_delta_amount=cumulative_account_delta_amount,
                        cumulative_account_delta_v=cumulative_account_delta_v,
                    )

                    session.add(audit_user_currency_liability)
                    currency_to_liability[account.currency] = audit_user_currency_liability
                    session.flush()  # populate defaults
                audit_currency_liability = currency_to_liability[account.currency]
                new_v = (
                    audit_currency_liability.cumulative_account_delta_v + account_delta.random_val
                ) % SECP256K1_ORDER
                audit_currency_liability.cumulative_account_delta_amount += account_delta.amount
                audit_currency_liability.cumulative_account_delta_v = new_v
            session.commit()
            return AddAccountDeltaGroupToAuditResponse(
                accountDeltaGroup=AccountDeltaGroupPB2(
                    id=account_delta_group.uuid.bytes,
                    userId=account_delta_group.user_uuid.bytes,
                    challengeRequest=challenge.challenge_request,
                    assertion=challenge.authenticator_assertion_response,
                    txnIds=txn_ids,
                    auditVersion=request.auditVersion,
                )
            )

    @admin_authenticated
    def ListAccountDeltaGroupsByAudit(
        self,
        request: ListAccountDeltaGroupsByAuditRequest,
        context: grpc.ServicerContext,
    ) -> ListAccountDeltaGroupsByAuditResponse:
        return self._list_account_delta_groups_by_audit(request, context, ADMIN_UUID)

    @admin_authenticated
    def GetAccountDeltaGroup(
        self,
        request: GetAccountDeltaGroupRequest,
        context: grpc.ServicerContext,
    ) -> GetAccountDeltaGroupResponse:
        account_delta_group_uuid = bytes_to_uuid(request.accountDeltaGroupId)
        with self._sessionmaker() as session:
            account_delta_group, challenge = (
                session.query(AccountDeltaGroup, Challenge)
                .filter(
                    AccountDeltaGroup.uuid == account_delta_group_uuid,
                    AccountDeltaGroup.audit_publish_version.isnot(None),
                    Challenge.uuid == AccountDeltaGroup.challenge_uuid,
                )
                .one()
            )
            blockchain_withdrawals = (
                session.query(BlockchainWithdrawal)
                .filter(
                    AccountDeltaGroupBlockchainTransaction.account_delta_group_uuid == account_delta_group.uuid,
                    AccountDeltaGroupBlockchainTransaction.blockchain_withdrawal_uuid == BlockchainWithdrawal.uuid,
                )
                .all()
            )
            blockchain_and_tx_params_to_txn_hash = {
                (
                    blockchain_withdrawal.blockchain,
                    blockchain_withdrawal.tx_params.SerializeToString(),
                ): blockchain_withdrawal.txn_hash
                for blockchain_withdrawal in blockchain_withdrawals
            }
            adgcr = AccountDeltaGroupChallengeRequest()
            assert challenge.challenge_request.request.Unpack(adgcr), "failed to unpack challenge"
            txn_ids = [
                blockchain_and_tx_params_to_txn_hash[(Blockchain[tx.blockchain], tx.txParams.SerializeToString())]
                for tx in adgcr.transactions
            ]
            return GetAccountDeltaGroupResponse(
                accountDeltaGroup=AccountDeltaGroupPB2(
                    id=account_delta_group.uuid.bytes,
                    userId=account_delta_group.user_uuid.bytes,
                    challengeRequest=challenge.challenge_request,
                    assertion=challenge.authenticator_assertion_response,
                    txnIds=txn_ids,
                    auditVersion=account_delta_group.audit_publish_version,
                )
            )
