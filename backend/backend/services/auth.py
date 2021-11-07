import logging

import grpc
import sqlalchemy.orm
from common.constants import ADMIN_UUID, Currency
from common.utils.uuid import bytes_to_uuid, generate_uuid4
from protobufs.account_pb2 import AccountType
from protobufs.institution.auth_pb2 import (
    LoginRequest,
    LoginResponse,
    MakeLoginChallengeRequest,
    MakeLoginChallengeResponse,
    MakeRegistrationChallengeRequest,
    MakeRegistrationChallengeResponse,
    RegisterRequest,
    RegisterResponse,
)
from protobufs.institution.auth_pb2_grpc import AuthServicer, add_AuthServicer_to_server
from protobufs.webauthn_pb2 import ChallengeRequest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from backend.sql.account import Account
from backend.sql.user import User
from backend.utils.jwt_client import JWTClient
from backend.utils.webauthn_client import AuthenticationFailedException, WebauthnClient

LOGGER = logging.getLogger(__name__)


class AuthService(AuthServicer):
    def __init__(
        self,
        sessionmaker: sqlalchemy.orm.sessionmaker,
        jwt_client: JWTClient,
        webauthn_client: WebauthnClient,
        server: grpc.Server,
    ):
        self._sessionmaker = sessionmaker
        self._jwt_client = jwt_client
        self._webauthn_client = webauthn_client
        add_AuthServicer_to_server(self, server)

    def MakeRegistrationChallenge(
        self, request: MakeRegistrationChallengeRequest, context: grpc.ServicerContext
    ) -> MakeRegistrationChallengeResponse:
        with self._sessionmaker() as session:
            username = request.username
            user_uuid = generate_uuid4()
            if username == "admin":
                LOGGER.info("Creating admin user")
                user_uuid = ADMIN_UUID
            user = User(user_uuid=user_uuid, username=username)
            session.add(user)
            challenge_request, credential_creation_request = self._webauthn_client.build_create_credential_request(
                session, user_uuid, username
            )
            try:
                session.commit()
            except IntegrityError as e:
                context.abort(grpc.StatusCode.ALREADY_EXISTS, "Username already taken.")
                raise ValueError("Username already taken.") from e

        return MakeRegistrationChallengeResponse(
            challengeRequest=challenge_request,
            credentialRequest=credential_creation_request,
        )

    def Register(self, request: RegisterRequest, context: grpc.ServicerContext) -> RegisterResponse:
        challenge_uuid = bytes_to_uuid(request.challengeNonce)
        with self._sessionmaker() as session:
            try:
                user_uuid = self._webauthn_client.validate_attestation_response(
                    session, challenge_uuid, request.attestation
                )
            except AuthenticationFailedException as e:
                LOGGER.error("Registration failed.", exc_info=True)
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Registration failed.")
                raise RuntimeError("Registration failed.") from e
            for currency in Currency:
                # create default accounts for the customer
                account = Account(
                    account_type=AccountType.DEPOSIT_ACCOUNT,
                    user_uuid=user_uuid,
                    currency=currency,
                )
                session.add(account)
            session.commit()
        return RegisterResponse(jwt=self._jwt_client.issue_auth_jwt(user_uuid))

    def MakeLoginChallenge(
        self, request: MakeLoginChallengeRequest, context: grpc.ServicerContext
    ) -> MakeLoginChallengeResponse:
        with self._sessionmaker() as session:
            username = request.username
            try:
                user = session.query(User).filter(User.username == username).one()
            except NoResultFound as e:
                context.abort(grpc.StatusCode.NOT_FOUND, "User not found.")
                raise ValueError("User not found.") from e
            user_uuid = user.user_uuid

            challenge_request, webauthn_challenge_request = self._webauthn_client.build_assertion_request(
                session, user_uuid=user_uuid, challenge_type=ChallengeRequest.ChallengeType.LOGIN
            )
            session.commit()
        return MakeLoginChallengeResponse(
            challengeRequest=challenge_request, credentialRequest=webauthn_challenge_request
        )

    def Login(self, request: LoginRequest, context: grpc.ServicerContext) -> LoginResponse:
        challenge_uuid = bytes_to_uuid(request.challengeNonce)
        with self._sessionmaker() as session:
            try:
                user_uuid = self._webauthn_client.validate_assertion_response(
                    session,
                    challenge_id=challenge_uuid,
                    challenge_type=ChallengeRequest.ChallengeType.LOGIN,
                    response=request.assertion,
                )
                session.commit()
            except AuthenticationFailedException as e:
                LOGGER.error("Login failed.", exc_info=True)
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Login failed.")
                raise RuntimeError("Login failed.") from e
            return LoginResponse(jwt=self._jwt_client.issue_auth_jwt(user_uuid))
