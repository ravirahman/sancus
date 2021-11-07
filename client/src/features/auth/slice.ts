import {
  createAsyncThunk, createSlice, ThunkDispatch, unwrapResult,
} from '@reduxjs/toolkit';
import { Action } from 'redux';

import * as AuthService from 'protobufs/institution/auth_pb_service';
import * as AuthPB from 'protobufs/institution/auth_pb';

import * as Webauthn from '../../utils/webauthn';
import { unary } from '../../utils/grpcClient';
import requireValue from '../../utils/requireValue';

type SliceState = { jwt?: string };

const initialState: SliceState = { jwt: undefined };

const login = createAsyncThunk<string, string, {state: SliceState}>(
  'auth/login',
  async (username: string) => {
    const makeLoginChallengeRequest = new AuthPB.MakeLoginChallengeRequest();
    makeLoginChallengeRequest.setUsername(username);
    const makeLoginChallengeResponse = await unary(
      AuthService.Auth.MakeLoginChallenge,
      makeLoginChallengeRequest,
    );
    const challengeRequest = requireValue(makeLoginChallengeResponse.getChallengerequest());
    const loginRequest = new AuthPB.LoginRequest();
    loginRequest.setChallengenonce(challengeRequest.getNonce());
    const credentialRequest = requireValue(makeLoginChallengeResponse.getCredentialrequest());
    const assertion = await Webauthn.requestAssertion(challengeRequest, credentialRequest);
    loginRequest.setAssertion(assertion);
    const loginResponse = await unary(AuthService.Auth.Login, loginRequest);
    const jwt = loginResponse.getJwt();
    return jwt;
  },
);

const register = createAsyncThunk<string, string, {state: SliceState}>(
  'auth/register',
  async (username: string) => {
    const makeRegistrationChallengeRequest = new AuthPB.MakeRegistrationChallengeRequest();
    makeRegistrationChallengeRequest.setUsername(username);
    const makeRegistrationChallengeResponse = await unary(
      AuthService.Auth.MakeRegistrationChallenge,
      makeRegistrationChallengeRequest,
    );
    const challengeRequest = requireValue(makeRegistrationChallengeResponse.getChallengerequest());
    const registerRequest = new AuthPB.RegisterRequest();
    const credentialRequest = requireValue(makeRegistrationChallengeResponse.getCredentialrequest());
    const attestation = await Webauthn.createCredential(credentialRequest);
    registerRequest.setAttestation(attestation);
    registerRequest.setChallengenonce(challengeRequest.getNonce());
    const registerResponse = await unary(AuthService.Auth.Register, registerRequest);
    const jwt = registerResponse.getJwt();
    return jwt;
  },
);

export const slice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    logout: (state) => {
      state.jwt = undefined;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(login.fulfilled, (state, action) => {
      state.jwt = action.payload;
    });
    builder.addCase(register.fulfilled, (state, action) => {
      state.jwt = action.payload;
    });
  },
});
export const mapDispatchToProps = (dispatch: ThunkDispatch<SliceState, undefined, Action>) => {
  return {
    logout: () => {
      return dispatch(slice.actions.logout());
    },
    login: async (username: string) => {
      return dispatch(login(username)).then(unwrapResult);
    },
    register: async (username: string) => {
      return dispatch(register(username)).then(unwrapResult);
    },
  };
};
export default slice.reducer;
