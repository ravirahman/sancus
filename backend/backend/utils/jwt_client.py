import base64
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Callable, Dict, Optional, Protocol, Tuple, Type, TypeVar

import google.protobuf.message
import grpc
import jwt
import jwt.exceptions
import pytz
from common.constants import ADMIN_UUID
from common.utils.datetime import (
    datetime_to_protobuf,
    get_current_datetime,
    protobuf_to_datetime,
)
from common.utils.uuid import generate_uuid4
from google.protobuf.any_pb2 import Any
from protobufs.institution.marketdata_pb2 import ExchangeRate
from protobufs.list_pb2 import NextToken

from backend.config import JWTConfig

JWT_EXPIRATION_TIME_CLAIM = "exp"
JWT_NOT_BEFORE_TIME_CLAIM = "nbf"
JWT_ISSUED_AT_CLAIM = "iat"
JWT_AUDIENCE_CLAIM = "aud"
JWT_ISSUER_CLAIM = "iss"
JWT_SUBJECT_CLAIM = "sub"
JWT_ID_CLAIM = "jti"

AUTHORIZATION_METADATA_KEY = "authorization"

AUTH_NAME = "AuthService"
MARKETDATA_NAME = "MarketdataService"
EXCHANGE_NAME = "ExchangeService"

EXCHANGE_RATE_PAYLOAD_KEY = "exchangeRate"
NEXT_TOKEN_PAYLOAD_KEY = "nextToken"

TOutputMessage = TypeVar("TOutputMessage", bound=google.protobuf.message.Message)


class JWTException(Exception):
    pass


class JWTClient:
    def __init__(self, config: JWTConfig) -> None:
        self._config = config
        with open(self._config.private_key_file, "r") as f:
            self._private_key = f.read()
        with open(self._config.public_key_file, "r") as f:
            self._public_key = f.read()

    def issue_auth_jwt(self, user_uuid: uuid.UUID) -> str:
        current_datetime = get_current_datetime()
        payload = {
            JWT_ISSUED_AT_CLAIM: int(current_datetime.timestamp()),
            JWT_NOT_BEFORE_TIME_CLAIM: int(current_datetime.timestamp()),
            JWT_EXPIRATION_TIME_CLAIM: int((current_datetime + self._config.auth_duration).timestamp()),
            JWT_ISSUER_CLAIM: AUTH_NAME,
            JWT_AUDIENCE_CLAIM: [AUTH_NAME],
            JWT_SUBJECT_CLAIM: user_uuid.hex,
            JWT_ID_CLAIM: generate_uuid4().hex,
        }
        user_jwt = jwt.encode(payload, self._private_key, algorithm=self._config.algorithm)
        return user_jwt

    def decode_auth_jwt(self, encoded_jwt: str) -> uuid.UUID:
        payload = self._decode_jwt(encoded_jwt, AUTH_NAME, user_uuid=None)
        user_uuid_str = payload[JWT_SUBJECT_CLAIM]
        assert isinstance(user_uuid_str, str)
        user_uuid = uuid.UUID(user_uuid_str)
        return user_uuid

    def issue_rate_jwt(self, user_uuid: uuid.UUID, exchange_rate: ExchangeRate, timestamp: datetime) -> str:
        serialized_exchange_rate = base64.b64encode(exchange_rate.SerializeToString()).decode("utf8")
        payload = {
            JWT_ISSUED_AT_CLAIM: int(timestamp.timestamp()),
            JWT_NOT_BEFORE_TIME_CLAIM: int(timestamp.timestamp()),
            JWT_EXPIRATION_TIME_CLAIM: int((timestamp + self._config.rate_duration).timestamp()),
            JWT_ISSUER_CLAIM: MARKETDATA_NAME,
            JWT_SUBJECT_CLAIM: user_uuid.hex,
            JWT_ID_CLAIM: generate_uuid4().hex,
            JWT_AUDIENCE_CLAIM: [MARKETDATA_NAME],
            EXCHANGE_RATE_PAYLOAD_KEY: serialized_exchange_rate,
        }
        rate_jwt = jwt.encode(payload, self._private_key, algorithm=self._config.algorithm)
        return rate_jwt

    def _decode_jwt(self, jwt_encoded: str, audience: str, user_uuid: Optional[uuid.UUID]) -> Dict[str, object]:
        assert isinstance(jwt_encoded, str)
        try:
            payload = jwt.decode(
                jwt_encoded,
                key=self._public_key,
                algorithms=[self._config.algorithm],
                audience=audience,
                leeway=timedelta(seconds=1),
            )
        except jwt.exceptions.DecodeError as e:
            raise JWTException("JWT decode failed") from e
        if user_uuid is not None and uuid.UUID(payload[JWT_SUBJECT_CLAIM]) != user_uuid:
            raise JWTException("user_uuid does not match the jwt")
        return payload

    def decode_rate_jwt(self, user_uuid: uuid.UUID, rate_jwt: str) -> Tuple[ExchangeRate, datetime]:
        payload = self._decode_jwt(rate_jwt, MARKETDATA_NAME, user_uuid)
        serialized_exchange_rate = payload[EXCHANGE_RATE_PAYLOAD_KEY]
        assert isinstance(serialized_exchange_rate, str)
        exchange_rate = ExchangeRate()
        exchange_rate.ParseFromString(base64.b64decode(serialized_exchange_rate.encode("utf8")))
        expiration_secs = payload[JWT_EXPIRATION_TIME_CLAIM]
        assert isinstance(expiration_secs, int)
        return exchange_rate, datetime.fromtimestamp(expiration_secs, pytz.UTC)

    def issue_next_token_jwt(
        self,
        initial_request_timestamp: datetime,
        user_uuid: uuid.UUID,
        token_type: str,
        req: google.protobuf.message.Message,
        offset: int,
    ) -> str:
        current_datetime = get_current_datetime()
        any_pb = Any()
        any_pb.Pack(req)
        next_token = NextToken(
            offset=offset, request=any_pb, initialRequestTimestamp=datetime_to_protobuf(initial_request_timestamp)
        )
        serialized_next_token = base64.b64encode(next_token.SerializeToString()).decode("utf8")
        payload = {
            JWT_ISSUED_AT_CLAIM: int(current_datetime.timestamp()),
            JWT_NOT_BEFORE_TIME_CLAIM: int(current_datetime.timestamp()),
            JWT_ISSUER_CLAIM: token_type,
            JWT_SUBJECT_CLAIM: user_uuid.hex,
            JWT_ID_CLAIM: generate_uuid4().hex,
            JWT_AUDIENCE_CLAIM: [token_type],
            NEXT_TOKEN_PAYLOAD_KEY: serialized_next_token,
        }
        next_token_jwt = jwt.encode(payload, self._private_key, algorithm=self._config.algorithm)
        return next_token_jwt

    def decode_next_token_jwt(
        self, user_uuid: uuid.UUID, token_type: str, next_token_jwt: str, req_type: Type[TOutputMessage]
    ) -> Tuple[datetime, int, TOutputMessage]:
        payload = self._decode_jwt(next_token_jwt, token_type, user_uuid)
        serialized_next_token = payload[NEXT_TOKEN_PAYLOAD_KEY]
        assert isinstance(serialized_next_token, str)
        next_token = NextToken()
        next_token.ParseFromString(base64.b64decode(serialized_next_token.encode("utf8")))
        offset = next_token.offset
        req = req_type()
        if not next_token.request.Unpack(req):
            raise RuntimeError(
                "Invalid request inside next token. Should never happen, since the backend packed the JWT."
            )
        initial_request_timestamp = protobuf_to_datetime(next_token.initialRequestTimestamp)
        return initial_request_timestamp, offset, req


class AuthenticatedServicer(Protocol):
    @property
    def jwt_client(self) -> JWTClient:
        pass


TAuthenticatedServicer = TypeVar("TAuthenticatedServicer", bound=AuthenticatedServicer, contravariant=True)
TRequest = TypeVar("TRequest", bound=google.protobuf.message.Message)
TResponse = TypeVar("TResponse", bound=google.protobuf.message.Message)

AuthenticatedHandler = Callable[
    [TAuthenticatedServicer, TRequest, grpc.ServicerContext, uuid.UUID],
    TResponse,
]

AdminAuthenticatedHandler = Callable[
    [TAuthenticatedServicer, TRequest, grpc.ServicerContext],
    TResponse,
]


def authenticated(
    handler: AuthenticatedHandler[TAuthenticatedServicer, TRequest, TResponse]
) -> Callable[[TAuthenticatedServicer, TRequest, grpc.ServicerContext], TResponse]:
    @wraps(handler)
    def wrapper(
        self: TAuthenticatedServicer,
        request: TRequest,
        context: grpc.ServicerContext,
    ) -> TResponse:
        jwt_client = self.jwt_client
        for k, v in context.invocation_metadata():
            if k == AUTHORIZATION_METADATA_KEY:
                assert isinstance(v, str)
                try:
                    user_uuid = jwt_client.decode_auth_jwt(v)
                except jwt.DecodeError as e:
                    context.abort(grpc.StatusCode.UNAUTHENTICATED, "authentication failed")
                    raise RuntimeError("authentication failed!") from e
                resp = handler(self, request, context, user_uuid)
                assert isinstance(resp, google.protobuf.message.Message)
                return resp
        context.abort(
            grpc.StatusCode.INVALID_ARGUMENT,
            f"missing {AUTHORIZATION_METADATA_KEY} metadatum",
        )
        raise RuntimeError(f"missing {AUTHORIZATION_METADATA_KEY} metadatum")

    return wrapper


def admin_authenticated(
    handler: AdminAuthenticatedHandler[TAuthenticatedServicer, TRequest, TResponse]
) -> Callable[[TAuthenticatedServicer, TRequest, grpc.ServicerContext], TResponse]:
    @wraps(handler)
    @authenticated
    def wrapper(
        self: TAuthenticatedServicer,
        request: TRequest,
        context: grpc.ServicerContext,
        user_uuid: uuid.UUID,
    ) -> TResponse:
        if user_uuid != ADMIN_UUID:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "not admin")
            raise RuntimeError("authentication failed!")
        resp = handler(self, request, context)
        assert isinstance(resp, google.protobuf.message.Message)
        return resp

    return wrapper
