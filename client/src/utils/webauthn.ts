import CryptoJS from 'crypto-js';

import * as WebauthnPB from 'protobufs/webauthn_pb';
import requireValue from './requireValue';
import { bufToHex } from './hex';

const unpackAlgorithm = (alg: WebauthnPB.AlgorithmMap[keyof WebauthnPB.AlgorithmMap]) => {
  switch (alg) {
  case WebauthnPB.Algorithm.ES256:
    return -7;
  case WebauthnPB.Algorithm.ES384:
    return -35;
  case WebauthnPB.Algorithm.ES512:
    return -36;
  case WebauthnPB.Algorithm.EDDSA:
    return -8;
  case WebauthnPB.Algorithm.RS256:
    return -257;
  default:
    throw new Error('invalid value for algorithm');
  }
};

const unpackKeyType = (
  keyType: WebauthnPB.PublicKeyCredentialTypeMap[keyof WebauthnPB.PublicKeyCredentialTypeMap],
): PublicKeyCredentialType => {
  switch (keyType) {
  case WebauthnPB.PublicKeyCredentialType.PUBLIC_KEY:
    return 'public-key';
  default:
    throw new Error('invalid keyType');
  }
};

const unpackAttestation = (attestation: WebauthnPB.AttestationMap[keyof WebauthnPB.AttestationMap]) => {
  switch (attestation) {
  case WebauthnPB.Attestation.NONE:
    return 'none';
  case WebauthnPB.Attestation.DIRECT:
    return 'direct';
  case WebauthnPB.Attestation.INDIRECT:
    return 'indirect';
  default:
    throw new Error('Invalid Attestation type');
  }
};

const unpackUserVerification = (
  userVerification: WebauthnPB.UserVerificationMap[keyof WebauthnPB.UserVerificationMap],
) => {
  switch (userVerification) {
  case WebauthnPB.UserVerification.REQUIRED:
    return 'required';
  case WebauthnPB.UserVerification.PREFERRED:
    return 'preferred';
  case WebauthnPB.UserVerification.DISCOURAGED:
    return 'discouraged';
  default:
    throw new Error('Invalid AuthenticatorSelectionCriteria.UserVerification type');
  }
};

const unpackTransport = (
  transport: WebauthnPB.AuthenticatorTransportMap[keyof WebauthnPB.AuthenticatorTransportMap],
) => {
  switch (transport) {
  case WebauthnPB.AuthenticatorTransport.BLE:
    return 'ble';
  case WebauthnPB.AuthenticatorTransport.NFC:
    return 'nfc';
  case WebauthnPB.AuthenticatorTransport.INTERNAL:
    return 'internal';
  case WebauthnPB.AuthenticatorTransport.USB:
    return 'usb';
  default:
    throw new Error(`Invalid PublicKeyCredentialDescriptor.AuthenticatorTransport ${transport}`);
  }
};

const unpackAuthenticatorAttachment = (
  attachment: WebauthnPB.AuthenticatorAttachmentMap[keyof WebauthnPB.AuthenticatorAttachmentMap],
) => {
  switch (attachment) {
  case WebauthnPB.AuthenticatorAttachment.INVALID_AUTHENTICATOR_ATTACHMENT:
    return undefined;
  case WebauthnPB.AuthenticatorAttachment.PLATFORM:
    return 'platform';
  case WebauthnPB.AuthenticatorAttachment.CROSS_PLATFORM:
    return 'cross-platform';
  default:
    throw new Error(`Invalid AuthenticatorAttachment ${attachment}`);
  }
};

export const createCredential = async (
  credentialRequest: WebauthnPB.PublicKeyCredentialCreationOptions,
): Promise<WebauthnPB.AuthenticatorAttestationResponse> => {
  const pubKeyCredParams = credentialRequest.getPubkeycredparamsList().map(
    (pubKeyCredParam) => {
      return {
        alg: unpackAlgorithm(pubKeyCredParam.getAlg()),
        type: unpackKeyType(pubKeyCredParam.getType()),
      };
    },
  );

  const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
    challenge: credentialRequest.getChallenge_asU8(),
    rp: {
      name: requireValue(credentialRequest.getRp()?.getName()),
      id: credentialRequest.getRp()?.getId(),
    },
    user: {
      id: requireValue(credentialRequest.getUser()?.getId_asU8()),
      name: requireValue(credentialRequest.getUser()?.getName()),
      displayName: requireValue(credentialRequest.getUser()?.getDisplayname()),
    },
    pubKeyCredParams,
    authenticatorSelection: {
      authenticatorAttachment: unpackAuthenticatorAttachment(
        requireValue(credentialRequest.getAuthenticatorselection()?.getAuthenticatorattachment()),
      ),
      userVerification: unpackUserVerification(
        requireValue(credentialRequest.getAuthenticatorselection()?.getUserverification()),
      ),
      requireResidentKey: credentialRequest.getAuthenticatorselection()?.getRequireresidentkey(),
    },
    timeout: credentialRequest.getTimeout(),
    attestation: unpackAttestation(credentialRequest.getAttestation()),
  };
  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions,
  }) as PublicKeyCredential;
  const response = credential.response as AuthenticatorAttestationResponse;
  const { clientDataJSON } = response;
  const { attestationObject } = response;
  const attestationResponse = new WebauthnPB.AuthenticatorAttestationResponse();
  attestationResponse.setAttestationobject(new Uint8Array(attestationObject));
  attestationResponse.setClientdata(new Uint8Array(clientDataJSON));
  return attestationResponse;
};

export const requestAssertion = async (
  challengeRequest: WebauthnPB.ChallengeRequest,
  credentialRequest: WebauthnPB.PublicKeyCredentialRequestOptions,
): Promise<WebauthnPB.AuthenticatorAssertionResponse> => {
  const challengeRequestBinary = challengeRequest.serializeBinary();
  const challengeRequestEnc = CryptoJS.enc.Hex.parse(bufToHex(challengeRequestBinary));
  const expectedChallengeHex = CryptoJS.SHA256(challengeRequestEnc).toString(CryptoJS.enc.Hex);
  const actualChallenge = credentialRequest.getChallenge_asU8();
  const actualChallengeHex = bufToHex(actualChallenge);
  if (expectedChallengeHex !== actualChallengeHex) {
    throw Error('Expected challenge did not match the actual challenge.');
  }

  const allowCredentials = credentialRequest.getAllowcredentialsList().map((pubKeyCredDescriptor) => {
    const transports = pubKeyCredDescriptor.getTransportsList().map(
      (transport) => {
        return unpackTransport(transport);
      },
    );
    return {
      id: pubKeyCredDescriptor.getId_asU8(),
      type: unpackKeyType(pubKeyCredDescriptor.getType()),
      transports,
    };
  });

  const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
    challenge: credentialRequest.getChallenge_asU8(),
    rpId: credentialRequest.getRpid(),
    userVerification: unpackUserVerification(credentialRequest.getUserverification()),
    timeout: credentialRequest.getTimeout(),
    allowCredentials,
  };
  const assertion = await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions,
  }) as PublicKeyCredential;
  const response = assertion.response as AuthenticatorAssertionResponse;
  const { clientDataJSON } = response;
  const { authenticatorData } = response;
  const webauthnChallengeResponse = new WebauthnPB.AuthenticatorAssertionResponse();
  webauthnChallengeResponse.setCredentialid(new Uint8Array(assertion.rawId));
  webauthnChallengeResponse.setAuthenticatordata(new Uint8Array(authenticatorData));
  webauthnChallengeResponse.setClientdata(new Uint8Array(clientDataJSON));
  webauthnChallengeResponse.setSignature(new Uint8Array(response.signature));
  return webauthnChallengeResponse;
};
