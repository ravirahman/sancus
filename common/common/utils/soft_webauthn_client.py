import hashlib
from typing import Dict, Optional

from protobufs.webauthn_pb2 import (
    Algorithm,
    Attestation,
    AuthenticatorAssertionResponse,
    AuthenticatorAttachment,
    AuthenticatorAttestationResponse,
    AuthenticatorTransport,
    ChallengeRequest,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialType,
    UserVerification,
)
from soft_webauthn import SoftWebauthnDevice


class SoftWebauthnClient:
    def __init__(self, origin: str) -> None:
        self._origin = origin
        self._cred_id_to_authenticator: Dict[bytes, SoftWebauthnDevice] = {}

    @staticmethod
    def _unpack_alg(alg: "Algorithm.V") -> int:
        if alg == Algorithm.ES256:
            return -7
        if alg == Algorithm.ES384:
            return -35
        if alg == Algorithm.ES512:
            return -36
        if alg == Algorithm.EDDSA:
            return -8
        if alg == Algorithm.RS256:
            return -257
        raise ValueError(f"invalid algorithm: {alg}")

    @staticmethod
    def _unpack_pubkey_cred_type(cred_type: "PublicKeyCredentialType.V") -> str:
        if cred_type == PublicKeyCredentialType.PUBLIC_KEY:
            return "public-key"
        raise ValueError(f"invalid cred_type: {cred_type}")

    @staticmethod
    def _unpack_attestation(attestation: "Attestation.V") -> str:
        if attestation == Attestation.NONE:
            return "none"
        if attestation == Attestation.INDIRECT:
            return "indirect"
        if attestation == Attestation.DIRECT:
            return "direct"
        raise ValueError(f"invalid attestation: {attestation}")

    @staticmethod
    def _unpack_authenticator_attachment(authenticator_attachment: "AuthenticatorAttachment.V") -> Optional[str]:
        if authenticator_attachment == AuthenticatorAttachment.INVALID_AUTHENTICATOR_ATTACHMENT:
            return None
        if authenticator_attachment == AuthenticatorAttachment.PLATFORM:
            return "platform"
        if authenticator_attachment == AuthenticatorAttachment.CROSS_PLATFORM:
            return "cross-platform"
        raise ValueError(f"invalid authenticator_attachment: {authenticator_attachment}")

    @staticmethod
    def _unpack_user_verification(user_verification: "UserVerification.V") -> str:
        if user_verification == UserVerification.REQUIRED:
            return "required"
        if user_verification == UserVerification.PREFERRED:
            return "preferred"
        if user_verification == UserVerification.DISCOURAGED:
            return "discouraged"
        raise ValueError(f"invalid user verification: {user_verification}")

    def create_credential(
        self, credential_request: PublicKeyCredentialCreationOptions
    ) -> AuthenticatorAttestationResponse:
        authenticator = SoftWebauthnDevice()
        response = authenticator.create(
            options={
                "publicKey": {
                    "challenge": credential_request.challenge,
                    "pubKeyCredParams": [
                        {
                            "alg": self._unpack_alg(cred_params.alg),
                            "type": self._unpack_pubkey_cred_type(cred_params.type),
                        }
                        for cred_params in credential_request.pubKeyCredParams
                    ],
                    "attestation": self._unpack_attestation(credential_request.attestation),
                    "rp": {
                        "name": credential_request.rp.name,
                        "id": credential_request.rp.id,
                    },
                    "user": {
                        "id": credential_request.user.id,
                        "name": credential_request.user.name,
                        "displayName": credential_request.user.displayName,
                    },
                    "authenticatorSelection": {
                        "authenticatorAttachment": self._unpack_authenticator_attachment(
                            credential_request.authenticatorSelection.authenticatorAttachment
                        ),
                        "userVerification": self._unpack_user_verification(
                            credential_request.authenticatorSelection.userVerification
                        ),
                        "requireResidentKey": credential_request.authenticatorSelection.requireResidentKey,
                    },
                    "timeout": credential_request.timeout,
                },
            },
            origin=self._origin,
        )
        credential_id: bytes = response["rawId"]
        self._cred_id_to_authenticator[credential_id] = authenticator
        return AuthenticatorAttestationResponse(
            clientData=response["response"]["clientDataJSON"],
            attestationObject=response["response"]["attestationObject"],
        )

    @staticmethod
    def _calculate_challenge_data(challenge_request: ChallengeRequest) -> bytes:
        m_challenge = hashlib.sha256()
        m_challenge.update(challenge_request.SerializeToString())
        challenge_data = m_challenge.digest()
        return challenge_data

    def request_assertion(
        self,
        challenge_request: ChallengeRequest,
        credential_request: PublicKeyCredentialRequestOptions,
    ) -> AuthenticatorAssertionResponse:
        expected_challenge_bytes = self._calculate_challenge_data(challenge_request)
        actual_challenge_bytes = credential_request.challenge
        if expected_challenge_bytes != actual_challenge_bytes:
            raise ValueError(
                f"expected_challenge_bytes({expected_challenge_bytes.hex()}) != "
                f"actual_challenge_bytes({actual_challenge_bytes.hex()})"
            )
        for allowed_credential in credential_request.allowCredentials:
            if allowed_credential.id not in self._cred_id_to_authenticator:
                continue
            assert allowed_credential.type == PublicKeyCredentialType.PUBLIC_KEY
            assert (
                AuthenticatorTransport.INTERNAL in allowed_credential.transports
            ), "internal transport must be allowed"
            assert credential_request.userVerification != UserVerification.REQUIRED, "required isn't supported"
            authenticator = self._cred_id_to_authenticator[allowed_credential.id]
            response = authenticator.get(
                options={
                    "publicKey": {
                        "rpId": credential_request.rpId,
                        "challenge": credential_request.challenge,
                    }
                },
                origin=self._origin,
            )
            return AuthenticatorAssertionResponse(
                clientData=response["response"]["clientDataJSON"],
                authenticatorData=response["response"]["authenticatorData"],
                credentialId=response["rawId"],
                signature=response["response"]["signature"],
            )
        raise ValueError("credential id not found")
