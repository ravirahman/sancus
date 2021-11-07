import logging
import secrets
import uuid
from decimal import Decimal
from typing import List, Optional, cast

import grpc
import petlib
import sqlalchemy.orm
from common.constants import (
    CURRENCY_PRECISIONS,
    SECP256K1_ALTERNATIVE_GENERATOR,
    SECP256K1_GENERATOR,
    SECP256K1_ORDER,
    Currency,
)
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid, generate_uuid4
from google.protobuf.any_pb2 import Any
from protobufs.account_pb2 import (
    AccountDeltaGroupChallengeRequest,
    AccountType,
    PublicAccountDeltaCommitment,
    RevealedAccountDeltaCommitment,
    RevealedPedersenCommitment,
)
from protobufs.institution.account_pb2 import (
    ExchangeTransaction,
    TransactionStatus,
    TransactionType,
)
from protobufs.institution.exchange_pb2 import (
    InitiateExchangeRequest,
    InitiateExchangeResponse,
    ProcessExchangeRequest,
    ProcessExchangeResponse,
)
from protobufs.institution.exchange_pb2_grpc import (
    ExchangeServicer,
    add_ExchangeServicer_to_server,
)
from protobufs.webauthn_pb2 import ChallengeRequest
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.account_delta import AccountDelta
from backend.sql.account_delta_group import AccountDeltaGroup
from backend.sql.challenge import Challenge
from backend.sql.transaction import Transaction
from backend.utils.jwt_client import (
    AuthenticatedServicer,
    JWTClient,
    JWTException,
    authenticated,
)
from backend.utils.webauthn_client import WebauthnClient

LOGGER = logging.getLogger(__name__)


class ExchangeService(ExchangeServicer, AuthenticatedServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        webauthn_client: WebauthnClient,
        account_anonymity_set_size: int,
        server: grpc.Server,
    ) -> None:
        super().__init__()
        self._sessionmaker = sessionmaker
        self._account_anonymity_set_size = account_anonymity_set_size
        self._webauthn_client = webauthn_client
        self._jwt_client = jwt_client
        add_ExchangeServicer_to_server(self, server)

    @property
    def jwt_client(self) -> JWTClient:
        return self._jwt_client

    @authenticated
    def InitiateExchange(
        self,
        request: InitiateExchangeRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> InitiateExchangeResponse:
        try:
            exchange_rate, exchange_rate_expiration = self._jwt_client.decode_rate_jwt(
                user_uuid, request.exchangeRateJWT
            )
        except JWTException as e:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid exchange rate JWT")
            raise ValueError("Invalid exchange rate JWT") from e
        from_currency = Currency[exchange_rate.fromCurrency]
        to_currency = Currency[exchange_rate.toCurrency]

        from_account_uuid = bytes_to_uuid(request.fromAccountId)
        to_account_uuid = bytes_to_uuid(request.toAccountId)
        if from_account_uuid == to_account_uuid:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "From account cannot be the same as the to account")
            raise ValueError("From account cannot be the same as the to account")
        rate = Decimal(exchange_rate.rate)

        account_delta_group_uuid = generate_uuid4()
        revealed_account_commitments: List[RevealedAccountDeltaCommitment] = []
        public_account_commitments: List[PublicAccountDeltaCommitment] = []
        with self._sessionmaker() as session:
            try:
                from_account = (
                    session.query(Account)
                    .filter(
                        Account.user_uuid == user_uuid,
                        Account.uuid == from_account_uuid,
                    )
                    .one()
                )
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "From account not found for user")
                raise ValueError("From account not found for user") from e
            if cast(Currency, from_account.currency) != from_currency:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Exchange rate from currency != from account currency")
                raise ValueError("Exchange rate from currency differs from account from currency")
            if from_account.account_type != AccountType.DEPOSIT_ACCOUNT:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "From account type must be a deposit account")
                raise ValueError("From account type must be a deposit account")

            try:
                to_account = (
                    session.query(Account)
                    .filter(
                        Account.user_uuid == user_uuid,
                        Account.uuid == to_account_uuid,
                    )
                    .one()
                )
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "To account not found for user")
                raise ValueError("To account not found for user") from e
            if cast(Currency, to_account.currency) != to_currency:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Exchange rate to currency != to account currency")
                raise ValueError("Exchange rate to currency != to account currency")

            decoy_accounts: List[Account] = []
            while len(decoy_accounts) < self._account_anonymity_set_size:
                query = session.query(Account).filter(
                    Account.user_uuid == user_uuid,
                    Account.uuid.notin_(
                        [from_account_uuid, to_account_uuid, *[account.uuid for account in decoy_accounts]]
                    ),
                )
                count = query.count()
                if count == 0:
                    break
                account = query.order_by(Account.created_at).offset(secrets.randbelow(count)).first()
                if account is not None:
                    decoy_accounts.append(account)

            def process_account(account: Account, amount: Decimal) -> None:
                random_val = SECP256K1_ORDER.random()
                currency = account.currency
                account_uuid = account.uuid
                amount = petlib.bn.Bn.from_decimal(str(int(amount * CURRENCY_PRECISIONS[currency])))
                commitment = amount * SECP256K1_GENERATOR + random_val * SECP256K1_ALTERNATIVE_GENERATOR
                account_delta = AccountDelta(
                    account_delta_group_uuid=account_delta_group_uuid,
                    account_uuid=account_uuid,
                    amount=amount,
                    random_val=random_val,
                )
                session.add(account_delta)
                public_account_commitments.append(
                    PublicAccountDeltaCommitment(accountId=account_uuid.bytes, commitment=commitment.export())
                )
                revealed_account_commitments.append(
                    RevealedAccountDeltaCommitment(
                        accountId=account_uuid.bytes,
                        commitment=RevealedPedersenCommitment(
                            r=str(random_val),
                            x=str(amount),
                        ),
                    )
                )

            process_account(from_account, -rate * Decimal(request.amount))
            process_account(to_account, Decimal(request.amount))
            for account in decoy_accounts:
                process_account(account, Decimal("0"))
            exchange_challenge_request = AccountDeltaGroupChallengeRequest(commitments=public_account_commitments)
            challenge_request, webauthn_challenge_request = self._webauthn_client.build_assertion_request(
                session,
                user_uuid=user_uuid,
                challenge_type=ChallengeRequest.ChallengeType.EXCHANGE,
                request=exchange_challenge_request,
                expiration=exchange_rate_expiration,
            )
            session.add(
                AccountDeltaGroup(
                    uuid=account_delta_group_uuid,
                    user_uuid=user_uuid,
                    status=TransactionStatus.PENDING,
                    challenge_uuid=bytes_to_uuid(challenge_request.nonce),
                )
            )
            session.commit()
        return InitiateExchangeResponse(
            id=account_delta_group_uuid.bytes,
            challengeRequest=challenge_request,
            revealedCommitments=revealed_account_commitments,
            credentialRequest=webauthn_challenge_request,
        )

    @authenticated
    def ProcessExchange(
        self,
        request: ProcessExchangeRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> ProcessExchangeResponse:
        account_delta_group_uuid = bytes_to_uuid(request.id)
        with self._sessionmaker() as session:
            account_delta_group = (
                session.query(AccountDeltaGroup)
                .filter(
                    AccountDeltaGroup.user_uuid == user_uuid,
                    AccountDeltaGroup.uuid == account_delta_group_uuid,
                )
                .one()
            )
            challenge_uuid = account_delta_group.challenge_uuid
            assert isinstance(challenge_uuid, uuid.UUID)
            webauthn_user_uuid = self._webauthn_client.validate_assertion_response(
                session,
                challenge_id=challenge_uuid,
                challenge_type=ChallengeRequest.ChallengeType.EXCHANGE,
                response=request.assertion,
            )
            if webauthn_user_uuid != user_uuid:
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "response signed by wrong user uuid")
                raise ValueError("invalid user signature")

            account_deltas = (
                session.query(AccountDelta)
                .filter(AccountDelta.account_delta_group_uuid == account_delta_group_uuid)
                .all()
            )

            from_account_delta: Optional[AccountDelta] = None
            to_account_delta: Optional[AccountDelta] = None
            challenge = session.query(Challenge).filter(Challenge.uuid == challenge_uuid).one()
            challenge_request = challenge.challenge_request

            for account_delta in account_deltas:
                amount = account_delta.amount
                assert amount is not None

                if amount < 0:
                    from_account_delta = account_delta
                if amount > 0:
                    to_account_delta = account_delta
                if from_account_delta is not None and to_account_delta is not None:
                    break

            assert from_account_delta is not None
            assert to_account_delta is not None
            timestamp = get_current_datetime()
            from_transaction_id = generate_uuid4()
            to_transaction_id = generate_uuid4()

            def build_transaction(
                my_account_delta: AccountDelta,
                my_id: uuid.UUID,
                other_account_delta: AccountDelta,
                other_id: uuid.UUID,
            ) -> Transaction:
                account = session.query(Account).filter(Account.uuid == my_account_delta.account_uuid).one()
                amount_bn = my_account_delta.amount
                assert amount_bn is not None
                currency = cast(Currency, account.currency)
                amount = Decimal(int(amount_bn)) / CURRENCY_PRECISIONS[currency]
                exchange_transaction = ExchangeTransaction(
                    accountDeltasRequestId=account_delta_group_uuid.bytes,
                    otherAccountId=other_account_delta.account_uuid.bytes,
                    otherTransactionId=other_id.bytes,
                    challengeRequest=challenge_request,
                    assertion=challenge.authenticator_assertion_response,
                )
                any_pb = Any()
                any_pb.Pack(exchange_transaction)
                transaction = Transaction(
                    uuid=my_id,
                    account_uuid=my_account_delta.account_uuid,
                    transaction_type=TransactionType.EXCHANGE,
                    timestamp=timestamp,
                    status=TransactionStatus.COMPLETED,
                    amount=amount,
                    extra=any_pb,
                )
                return transaction

            from_transaction = build_transaction(
                from_account_delta, from_transaction_id, to_account_delta, to_transaction_id
            )
            session.add(from_transaction)
            to_transaction = build_transaction(
                to_account_delta, to_transaction_id, from_account_delta, from_transaction_id
            )
            session.add(to_transaction)

            row_count = (
                session.query(AccountDeltaGroup)
                .filter(
                    AccountDeltaGroup.user_uuid == user_uuid,
                    AccountDeltaGroup.uuid == account_delta_group_uuid,
                    AccountDeltaGroup.status == TransactionStatus.PENDING,
                )
                .update(
                    {
                        AccountDeltaGroup.status: TransactionStatus.COMPLETED,
                    }
                )
            )
            if row_count != 1:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "bad request.id")
                raise ValueError("bad request.id")

            from_account = session.query(Account).filter(Account.uuid == from_account_delta.account_uuid).one()
            if from_account.available_amount + from_transaction.amount < 0:
                context.abort(grpc.StatusCode.UNAVAILABLE, "From account not sufficiently high")
                raise ValueError("From account not sufficiently high")
            row_count = (
                session.query(Account)
                .filter(Account.uuid == from_account.uuid, Account.available_amount == from_account.available_amount)
                .update({Account.available_amount: from_account.available_amount + from_transaction.amount})
            )
            if row_count != 1:
                context.abort(grpc.StatusCode.INTERNAL, "Race condition")
                raise RuntimeError("Race condition on updating from account balance. Try again")

            to_account = session.query(Account).filter(Account.uuid == to_account_delta.account_uuid).one()
            row_count = (
                session.query(Account)
                .filter(
                    Account.uuid == to_account_delta.account_uuid,
                    Account.available_amount == to_account.available_amount,
                )
                .update({Account.available_amount: to_account.available_amount + to_transaction.amount})
            )
            if row_count != 1:
                context.abort(grpc.StatusCode.INTERNAL, "Race condition")
                raise ValueError("Unable to credit destination account")
            session.commit()

        return ProcessExchangeResponse()
