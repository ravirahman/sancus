import {
  createSlice,
  createAsyncThunk,
  PayloadAction,
} from '@reduxjs/toolkit';

import * as Exchange from 'protobufs/institution/exchange_pb';
import * as ExchangeService from 'protobufs/institution/exchange_pb_service';
import * as MarketData from 'protobufs/institution//marketdata_pb';
import * as MarketDataService from 'protobufs/institution//marketdata_pb_service';
import jwt_decode from 'jwt-decode'; // eslint-disable-line camelcase

import * as Webauthn from '../../utils/webauthn';
import { unary } from '../../utils/grpcClient';
import requireValue from '../../utils/requireValue';

export type AccountWithDetails = {
  bytesId: Uint8Array,
  currency: string,
  available: string,
}

type SliceState = {
  fromAccount: AccountWithDetails | undefined,
  toAccount: AccountWithDetails | undefined,
  exchangeRateJWT: string | undefined,
  expiration: Date | undefined,
  rate: number | undefined,
};

type GetExchangeRateFuncArgs = {
  from: string,
  to: string,
  jwt: string,
}

type InitialExchangeFuncProps = {
  fromAccount: AccountWithDetails,
  toAccount: AccountWithDetails,
  amount: string,
  jwt: string,
  exchangeRateJWT: string,
};

const initialState: SliceState = {
  fromAccount: undefined,
  toAccount: undefined,
  exchangeRateJWT: undefined,
  expiration: undefined,
  rate: undefined,
};

type DecodedExchangeRateJWT = {
  exchangeRate: string,
  aud: string[],
  jti: string,
  sub: string,
  iss: string,
  exp: string,
  nbf: string,
  iat: string,
}

export const getExchangeRate = createAsyncThunk(
  'exchange/getExchangeRate',
  async (args: GetExchangeRateFuncArgs) => {
    const { from, to, jwt } = args;
    const getRateReq = new MarketData.GetMarketExchangeRateRequest();
    getRateReq.setFromcurrency(from);
    getRateReq.setTocurrency(to);
    const exchangeRateRes = await unary(
      MarketDataService.Marketdata.GetMarketExchangeRate,
      getRateReq,
      jwt,
    );
    return exchangeRateRes.getExchangeratejwt();
  },
);

export const makeExchange = createAsyncThunk(
  'exchange/makeExchange',
  async (args: InitialExchangeFuncProps) => {
    const {
      fromAccount,
      toAccount,
      amount,
      jwt,
      exchangeRateJWT,
    } = args;

    const { bytesId: fromBytesId } = fromAccount;
    const { bytesId: toBytesId } = toAccount;

    const initialExchangeRequest = new Exchange.InitiateExchangeRequest();
    initialExchangeRequest.setFromaccountid(fromBytesId);
    initialExchangeRequest.setToaccountid(toBytesId);
    initialExchangeRequest.setAmount(amount);
    initialExchangeRequest.setExchangeratejwt(exchangeRateJWT);

    const initiateExchangeResponse = await unary(
      ExchangeService.Exchange.InitiateExchange,
      initialExchangeRequest,
      jwt,
    );

    const challengeRequest = requireValue(initiateExchangeResponse.getChallengerequest());
    const credentialRequest = requireValue(initiateExchangeResponse.getCredentialrequest());
    const processExchangeRequest = new Exchange.ProcessExchangeRequest();
    const assertion = await Webauthn.requestAssertion(challengeRequest, credentialRequest);
    processExchangeRequest.setAssertion(assertion);
    processExchangeRequest.setId(initiateExchangeResponse.getId());

    const processExchangeResponse = await unary(
      ExchangeService.Exchange.ProcessExchange,
      processExchangeRequest,
      jwt,
    );

    return processExchangeResponse;
  },
);

export const exchangeSlice = createSlice({
  name: 'exchange',
  initialState,
  reducers: {
    setFromAccount: (state, action: PayloadAction<AccountWithDetails>) => {
      state.fromAccount = action.payload;
    },
    setToAccount: (state, action: PayloadAction<AccountWithDetails>) => {
      state.toAccount = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(getExchangeRate.fulfilled, (state, action) => {
      state.exchangeRateJWT = action.payload;
      const decodedRateObj: DecodedExchangeRateJWT = jwt_decode(action.payload);
      const buffer = Uint8Array.from(atob(decodedRateObj.exchangeRate), (c) => {
        return c.charCodeAt(0);
      });
      const exchangeRate = MarketData.ExchangeRate.deserializeBinary(buffer);
      state.rate = Number(exchangeRate.getRate());
      state.expiration = new Date(Number(decodedRateObj.exp) * 1000);
    });
  },
});

export const { setFromAccount, setToAccount } = exchangeSlice.actions;

export type AccountSetterFunctionType = typeof setFromAccount;

export default exchangeSlice.reducer;
