import logging
from datetime import datetime
from typing import List, Sequence

import grpc
import sqlalchemy.orm
from common.constants import CURRENCY_TO_BLOCKCHAIN, PAGINATION_LIMIT, Blockchain
from common.utils.datetime import datetime_to_protobuf
from common.utils.uuid import bytes_to_uuid
from protobufs.audit_pb2 import Audit as AuditPB2
from protobufs.audit_pb2 import KeyAccount as KeyAccountPB2
from protobufs.validator.auditor_pb2 import (
    GetAuditRequest,
    GetAuditResponse,
    GetLatestAuditVersionRequest,
    GetLatestAuditVersionResponse,
    ListKeyAccountsRequest,
    ListKeyAccountsResponse,
    ValidateUnsignedBlockchainTransactionRequest,
    ValidateUnsignedBlockchainTransactionResponse,
)
from protobufs.validator.auditor_pb2_grpc import (
    AuditorServicer,
    add_AuditorServicer_to_server,
)
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

from auditor.config import AuditorConfig
from auditor.sql.account import Account
from auditor.sql.audit import Audit
from auditor.sql.block import Block
from auditor.sql.key import Key
from auditor.sql.key_account_commitment import KeyAccountCommitment
from auditor.utils.blockchain_client.client import BlockchainClient
from auditor.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)


class ListKeyAccountsRPC(
    ListRPC[
        ListKeyAccountsRequest,
        ListKeyAccountsResponse,
        ListKeyAccountsRequest.Request,
        ListKeyAccountsResponse.Response,
    ]
):
    def __init__(self, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._sessionmaker = sessionmaker

    list_response_type = ListKeyAccountsResponse

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyAccountsRequest.Request,
        context: grpc.ServicerContext,
    ) -> Sequence[ListKeyAccountsResponse.Response]:
        return self.handle_subsequent_request(
            initial_request_timestamp=initial_request_timestamp,
            request=request,
            offset=0,
            context=context,
        )

    def handle_subsequent_request(
        self,
        initial_request_timestamp: datetime,
        request: ListKeyAccountsRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
    ) -> Sequence[ListKeyAccountsResponse.Response]:
        with self._sessionmaker() as session:
            filters = [
                KeyAccountCommitment.account_uuid == bytes_to_uuid(request.accountId),
                KeyAccountCommitment.audit_publish_version == Audit.version_number,
                Audit.finished.is_(True),
                KeyAccountCommitment.key_uuid == Key.key_uuid,
                KeyAccountCommitment.account_uuid == Account.uuid,
            ]
            if len(request.keyIds) > 0:
                filters.append(KeyAccountCommitment.key_uuid.in_([bytes_to_uuid(keyId) for keyId in request.keyIds]))
            results = (
                session.query(KeyAccountCommitment, Key, Account)
                .filter(*filters)
                .order_by(KeyAccountCommitment.key_uuid)
                .offset(offset)
                .limit(PAGINATION_LIMIT)
                .all()
            )
            answer: List[ListKeyAccountsResponse.Response] = []
            for key_account, key, account in results:
                answer.append(
                    ListKeyAccountsResponse.Response(
                        key=KeyAccountPB2(
                            keyId=key_account.key_uuid.bytes,
                            accountId=key_account.account_uuid.bytes,
                            ownershipCommitment=key_account.commitment.export(),
                            ownershipNIZK=key_account.nizk.serialize(),
                            blockNumber=key_account.block_number,
                            auditVersion=key_account.audit_publish_version,
                        ),
                        depositAddress=key.get_address(CURRENCY_TO_BLOCKCHAIN[account.currency]),
                    )
                )
            return answer


class AuditorService(AuditorServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        config: AuditorConfig,
        server: grpc.Server,
        blockchain_client: BlockchainClient,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._config = config
        self._blockchain_client = blockchain_client
        self._list_key_accounts_rpc = ListKeyAccountsRPC(self._sessionmaker)
        add_AuditorServicer_to_server(self, server)

    def GetLatestAuditVersion(
        self,
        request: GetLatestAuditVersionRequest,
        context: grpc.ServicerContext,
    ) -> GetLatestAuditVersionResponse:
        with self._sessionmaker() as session:
            latest_audit = (
                session.query(Audit).filter(Audit.finished.is_(True)).order_by(desc(Audit.version_number)).first()
            )
            if latest_audit is None:
                version = 0
            else:
                version = latest_audit.version_number
            return GetLatestAuditVersionResponse(version=version)

    def GetAudit(
        self,
        request: GetAuditRequest,
        context: grpc.ServicerContext,
    ) -> GetAuditResponse:
        if request.version < 1:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "version must be at least 1. version 0 is invalid")
            raise ValueError("invalid audit version")
        with self._sessionmaker() as session:
            try:
                audit = (
                    session.query(Audit).filter(Audit.finished.is_(True), Audit.version_number == request.version).one()
                )
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "audit not found for version")
                raise ValueError("audit not found for version") from e
            return GetAuditResponse(
                audit=AuditPB2(
                    bitcoinBlock=audit.bitcoin_block,
                    ethereumBlock=audit.ethereum_block,
                    timestamp=datetime_to_protobuf(audit.timestamp),
                    baseCurrency=audit.base_currency.name,
                    exchangeRates=audit.exchange_rates,
                    auditVersion=audit.version_number,
                )
            )

    def ValidateUnsignedBlockchainTransaction(
        self,
        request: ValidateUnsignedBlockchainTransactionRequest,
        context: grpc.ServicerContext,
    ) -> ValidateUnsignedBlockchainTransactionResponse:
        # for Etheruem, return true if the nonce is >= the transaction count
        # for bitcoin, return true if the txins are all unspent
        blockchain = Blockchain[request.transaction.blockchain]
        with self._sessionmaker() as session:
            try:
                block = (
                    session.query(Block).filter(Block.blockchain == blockchain).order_by(desc(Block.block_number)).one()
                )
            except NoResultFound as e:
                context.abort(grpc.StatusCode.UNAVAILABLE, "no blocks processed")
                raise RuntimeError("no blocks processed") from e
            block_metadata = self._blockchain_client.get_block_metadata_from_chain(blockchain, block.block_number)
            is_new_transaction = self._blockchain_client.is_new_transaction(
                blockchain, block_metadata, request.transaction.txParams
            )
            return ValidateUnsignedBlockchainTransactionResponse(
                blockNumber=block_metadata.block_number,
                blockHash=block_metadata.block_hash,
                wouldBeNew=is_new_transaction,
            )

    def ListKeyAccounts(
        self,
        request: ListKeyAccountsRequest,
        context: grpc.ServicerContext,
    ) -> ListKeyAccountsResponse:
        return self._list_key_accounts_rpc(request, context)
