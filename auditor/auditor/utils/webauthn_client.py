import base64
import hashlib
import logging
import uuid
from typing import Tuple, Type, TypeVar

import webauthn
from common.utils.uuid import bytes_to_uuid
from google.protobuf.message import Message
from hexbytes.main import HexBytes
from protobufs.webauthn_pb2 import AuthenticatorAssertionResponse, ChallengeRequest
from sqlalchemy.orm import Session
from webauthn.webauthn import AuthenticationRejectedException

from auditor.config import WebauthnConfig
from auditor.sql.challenge import Challenge
from auditor.sql.user_key import UserKey

LOGGER = logging.getLogger(__name__)

TMessage = TypeVar("TMessage", bound=Message)


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

    def _consume_challenge(
        self,
        session: Session,
        challenge_request: ChallengeRequest,
        challenge_type: "ChallengeRequest.ChallengeType.V",
        challenge_request_payload_type: Type[TMessage],
    ) -> Tuple[uuid.UUID, bytes, TMessage]:
        challenge_nonce = HexBytes(challenge_request.nonce)
        # this add will fail if the challenge was already used
        session.add(Challenge(challenge_nonce=challenge_nonce))
        challenge_request_type = challenge_request.challengeType

        if challenge_request_type != challenge_type:
            raise AuthenticationFailedException("Incorrect challenge type")
        user_uuid = bytes_to_uuid(challenge_request.userId)

        challenge_request_payload = challenge_request_payload_type()
        challenge_request_payload_any_pb = challenge_request.request
        if not challenge_request_payload_any_pb.Unpack(challenge_request_payload):
            raise RuntimeError("Failed to unpack payload to PB")
        challenge_data = self._calculate_challenge_data(challenge_request)
        return user_uuid, challenge_data, challenge_request_payload

    def validate_assertion_response(
        self,
        session: Session,
        challenge_request: ChallengeRequest,
        challenge_type: "ChallengeRequest.ChallengeType.V",
        response: AuthenticatorAssertionResponse,
        audit_version: int,
        challenge_request_payload_type: Type[TMessage],
    ) -> Tuple[uuid.UUID, TMessage]:
        user_uuid, challenge_data, challenge_request_payload = self._consume_challenge(
            session, challenge_request, challenge_type, challenge_request_payload_type
        )

        credential_id = response.credentialId

        user_keys = (
            session.query(UserKey)
            .filter(
                UserKey.credential_id == credential_id,
                UserKey.audit_publish_version <= audit_version,
                UserKey.user_uuid == user_uuid,
            )
            .all()
        )

        for user_key in user_keys:
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
                sign_count=0,  # we don't validate sign count since transactions can be included out-of-order
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
                webauthn_assertion_response.verify()
            except AuthenticationRejectedException as e:
                LOGGER.warning("webauthn signature validation failed", stack_info=True, exc_info=e)
                # this credential id didn't work, try the next one
                continue
            else:
                return user_uuid, challenge_request_payload
        raise AuthenticationFailedException("credential id is invalid")
