import base64
import hashlib
import logging
import uuid
from datetime import datetime
from typing import List, Optional, Tuple

import google.protobuf.message
import webauthn
from common.utils.datetime import get_current_datetime
from common.utils.uuid import bytes_to_uuid, generate_uuid4
from google.protobuf.any_pb2 import Any
from protobufs.webauthn_pb2 import (
    Algorithm,
    Attestation,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    ChallengeRequest,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    UserVerification,
)
from sqlalchemy.orm import Session
from webauthn.webauthn import AuthenticationRejectedException

from backend.config import WebauthnConfig
from backend.sql.challenge import Challenge
from backend.sql.user_key import UserKey

LOGGER = logging.getLogger(__name__)


class AuthenticationFailedException(Exception):
    pass


class WebauthnClient:
    def __init__(self, config: WebauthnConfig) -> None:
        self._config = config

    @staticmethod
    def _calculate_challenge_data(challenge_request: ChallengeRequest) -> bytes:
        m_challenge = hashlib.sha256()
        m_challenge.update(challenge_request.SerializeToString())
        challenge_data = m_challenge.digest()
        return challenge_data

    def build_create_credential_request(
        self,
        session: Session,
        user_uuid: uuid.UUID,
        username: str,
    ) -> Tuple[ChallengeRequest, PublicKeyCredentialCreationOptions]:
        challenge_id = generate_uuid4()
        challenge_request = ChallengeRequest(
            challengeType=ChallengeRequest.ChallengeType.REGISTRATION,
            nonce=challenge_id.bytes,
            userId=user_uuid.bytes,
        )
        challenge_data = self._calculate_challenge_data(challenge_request)
        challenge = Challenge(
            uuid=challenge_id,
            expiration=get_current_datetime() + self._config.challenge_duration,
            challenge_request=challenge_request,
        )
        session.add(challenge)
        rp = PublicKeyCredentialRpEntity(name=self._config.rp_name, id=self._config.rp_id)

        credential_request = PublicKeyCredentialCreationOptions(
            challenge=challenge_data,
            rp=rp,
            user=PublicKeyCredentialUserEntity(id=user_uuid.bytes, name=username, displayName=username),
            pubKeyCredParams=[
                PublicKeyCredentialParameters(
                    alg=Algorithm.ES512,
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                ),
                PublicKeyCredentialParameters(
                    alg=Algorithm.ES384,
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                ),
                PublicKeyCredentialParameters(
                    alg=Algorithm.ES256,
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                ),
                PublicKeyCredentialParameters(
                    alg=Algorithm.RS256,
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                ),
            ],
            timeout=int(self._config.timeout.total_seconds() * 1000),
            attestation=Attestation.NONE,
            authenticatorSelection=AuthenticatorSelectionCriteria(
                userVerification=UserVerification.DISCOURAGED,
                requireResidentKey=False,
            ),
        )
        return challenge_request, credential_request

    def validate_attestation_response(
        self,
        session: Session,
        challenge_uuid: uuid.UUID,
        response: AuthenticatorAttestationResponse,
    ) -> uuid.UUID:
        user_uuid, challenge_data = self._consume_challenge(
            session,
            challenge_uuid,
            ChallengeRequest.ChallengeType.REGISTRATION,
        )

        registration_response = {
            "clientData": base64.urlsafe_b64encode(response.clientData),
            "attObj": base64.urlsafe_b64encode(response.attestationObject),
        }
        webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
            rp_id=self._config.rp_id,
            origin=self._config.origin,
            registration_response=registration_response,
            challenge=base64.urlsafe_b64encode(challenge_data).rstrip(b"=").decode("utf8"),
            trusted_attestation_cert_required=False,
            self_attestation_permitted=True,
            none_attestation_permitted=True,
            expected_registration_client_extensions=set(),
            expected_registration_authenticator_extensions=set(),
        )
        webauthn_credential = webauthn_registration_response.verify()
        credential_id = webauthn.webauthn._webauthn_b64_decode(  # pylint: disable=protected-access
            webauthn_credential.credential_id
        )
        public_key = webauthn_credential.public_key
        user_key = UserKey(
            credential_id=credential_id,
            public_key=public_key,
            user_uuid=user_uuid,
            attestation=response,
            credential_type=PublicKeyCredentialType.PUBLIC_KEY,  # TODO(ravi.rahman) don't hardcode this
        )
        session.add(user_key)
        assert isinstance(user_uuid, uuid.UUID)
        return user_uuid

    def build_assertion_request(
        self,
        session: Session,
        user_uuid: uuid.UUID,
        challenge_type: "ChallengeRequest.ChallengeType.V",
        request: Optional[google.protobuf.message.Message] = None,
        expiration: Optional[datetime] = None,
    ) -> Tuple[ChallengeRequest, PublicKeyCredentialRequestOptions]:
        challenge_uuid = generate_uuid4()
        any_request: Optional[Any] = None
        if request is not None:
            any_request = Any()
            any_request.Pack(request)

        challenge_request = ChallengeRequest(
            challengeType=challenge_type,
            nonce=challenge_uuid.bytes,
            request=any_request,
            userId=user_uuid.bytes,
        )
        if expiration is None:
            expiration = get_current_datetime() + self._config.challenge_duration
        challenge = Challenge(
            uuid=challenge_uuid,
            challenge_request=challenge_request,
            expiration=expiration,
        )
        session.add(challenge)

        allow_credentials: List[PublicKeyCredentialDescriptor] = []
        for allow_credential in session.query(UserKey).filter(UserKey.user_uuid == user_uuid).all():
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=allow_credential.credential_id,
                    type=allow_credential.credential_type,
                    transports=[
                        AuthenticatorTransport.USB,
                        AuthenticatorTransport.NFC,
                        AuthenticatorTransport.BLE,
                        AuthenticatorTransport.INTERNAL,
                    ],
                )
            )
        webauthn_req = PublicKeyCredentialRequestOptions(
            challenge=self._calculate_challenge_data(challenge_request),
            rpId=self._config.rp_id,
            timeout=int(self._config.timeout.total_seconds() * 1000),
            userVerification=UserVerification.DISCOURAGED,
            allowCredentials=allow_credentials,
        )
        return challenge_request, webauthn_req

    def _consume_challenge(
        self,
        session: Session,
        challenge_id: uuid.UUID,
        challenge_type: "ChallengeRequest.ChallengeType.V",
        authenticator_assertion_response: Optional[AuthenticatorAssertionResponse] = None,
        challenge_request_payload: Optional[google.protobuf.message.Message] = None,
    ) -> Tuple[uuid.UUID, bytes]:
        challenge = (
            session.query(Challenge)
            .filter(
                Challenge.uuid == challenge_id,
                Challenge.expiration > get_current_datetime(),
                Challenge.used_at.is_(None),
            )
            .populate_existing()
            .with_for_update()
            .one()
        )
        user_uuid = bytes_to_uuid(challenge.challenge_request.userId)
        if challenge_type != ChallengeRequest.ChallengeType.REGISTRATION and authenticator_assertion_response is None:
            raise TypeError("authenticator_assertion_response is None and challengeType != registration")
        challenge.used_at = get_current_datetime()
        challenge.authenticator_assertion_response = authenticator_assertion_response
        challenge_request = challenge.challenge_request
        challenge_request_type = challenge_request.challengeType
        if challenge_request_type != challenge_type:
            raise AuthenticationFailedException("Incorrect challenge type")
        challenge_request_nonce = challenge_request.nonce
        if challenge_id.bytes != challenge_request_nonce:
            raise RuntimeError("Challenge id should always be the request nonce")

        if challenge_request_payload is not None:
            challenge_request_payload_any_pb = challenge_request.request
            if not challenge_request_payload_any_pb.Unpack(challenge_request_payload):
                raise RuntimeError("Failed to unpack payload to PB")
        challenge_data = self._calculate_challenge_data(challenge_request)
        return user_uuid, challenge_data

    def validate_assertion_response(
        self,
        session: Session,
        challenge_id: uuid.UUID,
        challenge_type: "ChallengeRequest.ChallengeType.V",
        response: AuthenticatorAssertionResponse,
        challenge_request_payload: Optional[google.protobuf.message.Message] = None,
    ) -> uuid.UUID:
        user_uuid, challenge_data = self._consume_challenge(
            session, challenge_id, challenge_type, response, challenge_request_payload
        )

        credential_id = response.credentialId

        user_keys = (
            session.query(UserKey)
            .filter(
                UserKey.credential_id == credential_id,
                UserKey.user_uuid == user_uuid,
            )
            .all()
        )
        for user_key in user_keys:
            sign_count = user_key.sign_count
            assert isinstance(sign_count, int)

            base64_credential_id = base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode("utf8")
            base64_challenge = base64.urlsafe_b64encode(challenge_data).rstrip(b"=").decode("utf8")

            assertion_response = {
                "id": base64_credential_id,
                "clientData": base64.urlsafe_b64encode(response.clientData),
                "authData": base64.urlsafe_b64encode(response.authenticatorData),
                "signature": response.signature.hex(),
            }

            webauthn_user = webauthn.WebAuthnUser(
                user_uuid,
                username="username",
                display_name="displayname",
                icon_url=None,
                credential_id=base64_credential_id,
                public_key=user_key.public_key,
                sign_count=sign_count,
                rp_id=self._config.rp_id,
            )

            webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
                webauthn_user,
                assertion_response,
                base64_challenge,
                self._config.origin,
                uv_required=False,
            )
            try:
                new_sign_count = webauthn_assertion_response.verify()
            except AuthenticationRejectedException:
                # this credential id didn't work, try the next one
                continue
            else:
                locked_user_key = (
                    session.query(UserKey)
                    .filter(
                        UserKey.user_key_uuid == user_key.user_key_uuid,
                        UserKey.sign_count == sign_count,
                    )
                    .populate_existing()
                    .with_for_update()
                    .one()
                )
                locked_user_key.sign_count = new_sign_count
                return user_uuid
        raise AuthenticationFailedException("credential id is invalid")
