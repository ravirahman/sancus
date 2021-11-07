import logging
import uuid
from datetime import datetime
from decimal import Decimal
from typing import List, Mapping, Optional, Sequence

import grpc
import petlib
import sqlalchemy.orm
from common.constants import (
    ADMIN_UUID,
    CURRENCY_TO_BLOCKCHAIN,
    PAGINATION_LIMIT,
    Currency,
)
from common.utils.datetime import protobuf_to_datetime
from common.utils.uuid import bytes_to_uuid
from protobufs.account_pb2 import RevealedPedersenCommitment
from protobufs.institution.deposit_pb2 import (
    DepositFromFaucetRequest,
    DepositFromFaucetResponse,
    ListDepositKeysRequest,
    ListDepositKeysResponse,
    MakeDepositKeyRequest,
    MakeDepositKeyResponse,
    RevealedDepositKey,
)
from protobufs.institution.deposit_pb2_grpc import (
    DepositServicer,
    add_DepositServicer_to_server,
)
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.key import Key
from backend.sql.key_account_commitment import KeyAccountCommitment
from backend.utils.blockchain_client.client import BlockchainClient
from backend.utils.jwt_client import AuthenticatedServicer, JWTClient, authenticated
from backend.utils.key_client import KeyClient
from backend.utils.list_rpc import ListRPC

LOGGER = logging.getLogger(__name__)
LIST_DEPOSIT_KEYS_NEXT_TOKEN_TYPE = "ListDepositKeys"


class ListDepositKeys(
    ListRPC[ListDepositKeysRequest, ListDepositKeysResponse, ListDepositKeysRequest.Request, RevealedDepositKey]
):
    def __init__(self, jwt_client: JWTClient, sessionmaker: sqlalchemy.orm.sessionmaker):
        self._jwt_client = jwt_client
        self._sessionmaker = sessionmaker

    next_token_name = LIST_DEPOSIT_KEYS_NEXT_TOKEN_TYPE
    list_response_type = ListDepositKeysResponse

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    def handle_initial_request(
        self,
        initial_request_timestamp: datetime,
        request: ListDepositKeysRequest.Request,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[RevealedDepositKey]:
        account_uuid = bytes_to_uuid(request.accountId)
        with self._sessionmaker() as session:
            try:
                session.query(Account).filter(Account.user_uuid == user_uuid, Account.uuid == account_uuid).one()
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "account not found for user")
                raise ValueError("account not found for user") from e
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
        request: ListDepositKeysRequest.Request,
        offset: int,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> Sequence[RevealedDepositKey]:
        account_uuid = bytes_to_uuid(request.accountId)
        from_timestamp = protobuf_to_datetime(request.fromTimestamp)
        to_timestamp = protobuf_to_datetime(request.toTimestamp)
        if from_timestamp >= to_timestamp:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "fromTimestamp >= toTimestamp")
            raise ValueError("fromTimestamp >= toTimestamp")
        with self._sessionmaker() as session:
            results = (
                session.query(Key, Account, KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.account_uuid == account_uuid,
                    KeyAccountCommitment.created_at >= from_timestamp,
                    KeyAccountCommitment.created_at < to_timestamp,
                    KeyAccountCommitment.s.is_(True),  # only want to return owned accounts back to the user
                    Key.key_uuid == KeyAccountCommitment.key_uuid,
                    Account.uuid == KeyAccountCommitment.account_uuid,
                )
                .order_by(desc(KeyAccountCommitment.created_at))
                .limit(PAGINATION_LIMIT)
                .offset(offset)
                .all()
            )

            revealed_deposit_keys: List[RevealedDepositKey] = []
            for key, account, key_account_commitment in results:
                address = key.get_address(CURRENCY_TO_BLOCKCHAIN[account.currency])
                r = key_account_commitment.r
                s = key_account_commitment.s
                revealed_deposit_keys.append(
                    RevealedDepositKey(
                        keyId=key.key_uuid.bytes,
                        address=address,
                        ownershipCommitment=RevealedPedersenCommitment(
                            x=str(petlib.bn.Bn(s)),
                            r=str(r),
                        ),
                    )
                )
            return revealed_deposit_keys


class DepositService(DepositServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        key_client: KeyClient,
        blockchain_client: BlockchainClient,
        deposit_faucet_amounts: Optional[Mapping[Currency, Decimal]],
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._deposit_faucet_amounts = deposit_faucet_amounts
        self._jwt_client = jwt_client
        self._key_client = key_client
        self._blockchain_client = blockchain_client
        self._list_deposit_keys = ListDepositKeys(jwt_client, sessionmaker)
        add_DepositServicer_to_server(self, server)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @authenticated
    def MakeDepositKey(
        self,
        request: MakeDepositKeyRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> MakeDepositKeyResponse:
        account_uuid = bytes_to_uuid(request.accountId)
        with self._sessionmaker() as session:
            try:
                session.query(Account).filter(
                    Account.user_uuid == user_uuid,
                    Account.uuid == account_uuid,
                ).one()
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "account not found for user")
                raise ValueError("account not found for user") from e
        key_uuid = self._key_client.find_or_create_key_and_assign_to_account(account_uuid)
        with self._sessionmaker() as session:
            key = session.query(Key).filter(Key.key_uuid == key_uuid).one()
            account, key_account_commitment = (
                session.query(Account, KeyAccountCommitment)
                .filter(
                    KeyAccountCommitment.key_uuid == key_uuid,
                    KeyAccountCommitment.account_uuid == account_uuid,
                    KeyAccountCommitment.account_uuid == Account.uuid,
                )
                .one()
            )
            address = key.get_address(CURRENCY_TO_BLOCKCHAIN[account.currency])
            r = key_account_commitment.r
            s = key_account_commitment.s
            assert s == (user_uuid != ADMIN_UUID), "key should be assigned to the account"
            return MakeDepositKeyResponse(
                depositKey=RevealedDepositKey(
                    keyId=key.key_uuid.bytes,
                    address=address,
                    ownershipCommitment=RevealedPedersenCommitment(
                        x=str(petlib.bn.Bn(s)),
                        r=str(r),
                    ),
                )
            )

    @authenticated
    def ListDepositKeys(
        self,
        request: ListDepositKeysRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> ListDepositKeysResponse:
        return self._list_deposit_keys(request, context, user_uuid)

    def DepositFromFaucet(
        self, request: DepositFromFaucetRequest, context: grpc.ServicerContext
    ) -> DepositFromFaucetResponse:
        currency = Currency[request.currency]
        if self._deposit_faucet_amounts is None:
            context.abort(grpc.StatusCode.UNAVAILABLE, "no faucets available")
            raise RuntimeError("no faucets available")
        if currency not in self._deposit_faucet_amounts:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"currency {currency} does not have a faucet")
            raise ValueError(f"currency {currency} does not have a faucet")
        self._blockchain_client.deposit(request.address, currency, self._deposit_faucet_amounts[currency])
        return DepositFromFaucetResponse()
