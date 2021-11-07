import unittest
from unittest.mock import patch

import grpc
from common.constants import Currency
from protobufs.institution.auth_pb2 import (
    LoginRequest,
    MakeLoginChallengeRequest,
    MakeRegistrationChallengeRequest,
    MakeRegistrationChallengeResponse,
    RegisterRequest,
)
from protobufs.institution.auth_pb2_grpc import AuthStub

from backend.backend import Backend
from backend.sql.account import Account
from backend.sql.challenge import Challenge
from tests.base import BaseBackendTestCase
from tests.fixtures import MOCK_USER_UUID, mock_generate_uuid4, mock_generated_uuids


@patch("common.utils.uuid._generate_uuid4", mock_generate_uuid4)
class TestAuth(BaseBackendTestCase):
    auth_stub: AuthStub
    channel: grpc.Channel
    backend: Backend

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.auth_stub = AuthStub(cls.channel)

    def test_make_registration_challenge(self) -> None:
        request = MakeRegistrationChallengeRequest(username="register_username")
        response = self.auth_stub.MakeRegistrationChallenge(request)
        challenge_uuid = mock_generated_uuids[-1]
        self.assertEqual(response.challengeRequest.nonce, challenge_uuid.bytes)
        with self.backend.sessionmaker() as session:
            session.query(Challenge).filter(
                Challenge.uuid == challenge_uuid,
            ).one()  # validate that the challenge is there

    def test_register(self) -> None:
        request = MakeRegistrationChallengeRequest(username="register_username")
        response: MakeRegistrationChallengeResponse = self.auth_stub.MakeRegistrationChallenge(request)
        attestation = self.soft_webauthn.create_credential(response.credentialRequest)
        register_request = RegisterRequest(challengeNonce=response.challengeRequest.nonce, attestation=attestation)
        register_response = self.auth_stub.Register(register_request)
        user_uuid = self.backend.jwt_client.decode_auth_jwt(register_response.jwt)
        with self.backend.sessionmaker() as session:
            accounts = session.query(Account).filter(Account.user_uuid == user_uuid).all()
            self.assertEqual(len(accounts), len(Currency))

    def test_make_login_challenge(self) -> None:
        request = MakeLoginChallengeRequest(username="test_user")
        response = self.auth_stub.MakeLoginChallenge(request)
        challenge_uuid = mock_generated_uuids[-1]
        self.assertEqual(response.challengeRequest.nonce, challenge_uuid.bytes)

    def test_login(self) -> None:
        request = MakeLoginChallengeRequest(username="test_user")
        response = self.auth_stub.MakeLoginChallenge(request)
        assertion = self.soft_webauthn.request_assertion(response.challengeRequest, response.credentialRequest)
        login_request = LoginRequest(challengeNonce=response.challengeRequest.nonce, assertion=assertion)
        login_response = self.auth_stub.Login(login_request)
        user_uuid = self.backend.jwt_client.decode_auth_jwt(login_response.jwt)
        self.assertEqual(user_uuid, MOCK_USER_UUID)


if __name__ == "__main__":
    unittest.main()
