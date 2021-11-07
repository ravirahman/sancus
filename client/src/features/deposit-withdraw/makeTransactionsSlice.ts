import {
  createAsyncThunk, createSlice,
} from '@reduxjs/toolkit';
import { RevealedDepositKey } from 'protobufs/institution/deposit_pb';

import * as Deposit from 'protobufs/institution/deposit_pb';
import * as DepositService from 'protobufs/institution/deposit_pb_service';
import * as Withdrawal from 'protobufs/institution/withdrawal_pb';
import * as WithdrawalService from 'protobufs/institution/withdrawal_pb_service';
import { Timestamp } from 'google-protobuf/google/protobuf/timestamp_pb';

import * as Webauthn from '../../utils/webauthn';
import { unary } from '../../utils/grpcClient';
import requireValue from '../../utils/requireValue';

type MakeDepositKeyParam = {
  jwt: string,
  accountID: Uint8Array,
}

type makeWithdrawalParam = {
  jwt: string,
  accountID: Uint8Array,
  destination: string,
  amount: string,
}

type makeFaucetReqParam = {
  jwt: string,
  currency: string,
  address: string,
}

type SliceState = {
  depositKeys: RevealedDepositKey[],
};

const initialState: SliceState = {
  depositKeys: [],
};

export const makeDepositKey = createAsyncThunk(
  'transact/makeDepositKey',
  async (args: MakeDepositKeyParam) => {
    const { jwt, accountID } = args;

    const makeDepositKeyRequest = new Deposit.MakeDepositKeyRequest();
    makeDepositKeyRequest.setAccountid(accountID);
    const makeDepositKeyResponse = await unary(
      DepositService.Deposit.MakeDepositKey,
      makeDepositKeyRequest,
      jwt,
    );
    const depositKey = makeDepositKeyResponse.getDepositkey();
    return depositKey;
  },
);

export const listDepositKeys = createAsyncThunk(
  'transact/listDepositKeys',
  async (args: MakeDepositKeyParam) => {
    const { jwt, accountID } = args;
    const listDepositKeyRequest = new Deposit.ListDepositKeysRequest();
    const request = new Deposit.ListDepositKeysRequest.Request();
    request.setAccountid(accountID);

    const zeroTimestamp = new Timestamp();
    const nowTimestamp = new Timestamp();
    zeroTimestamp.fromDate(new Date(0));
    nowTimestamp.fromDate(new Date());

    request.setFromtimestamp(zeroTimestamp);
    request.setTotimestamp(nowTimestamp);

    listDepositKeyRequest.setRequest(request);
    const listDepositKeyResponse = await unary(
      DepositService.Deposit.ListDepositKeys,
      listDepositKeyRequest,
      jwt,
    );
    const depositKeys = listDepositKeyResponse.getResponseList();

    let nextToken = listDepositKeyResponse.getNexttoken();
    /* eslint-disable no-await-in-loop */
    while (nextToken) {
      const newlistKeysRequest = new Deposit.ListDepositKeysRequest();
      newlistKeysRequest.setNexttoken(nextToken);
      const nextResponse = await unary(
        DepositService.Deposit.ListDepositKeys,
        newlistKeysRequest,
        jwt,
      );
      nextToken = nextResponse.getNexttoken();
      depositKeys.push(...nextResponse.getResponseList());
    }
    return depositKeys;
  },
);

export const makeWithdrawal = createAsyncThunk(
  'transact/makeWithdrawal',
  async (args: makeWithdrawalParam) => {
    const {
      jwt,
      accountID,
      destination,
      amount,
    } = args;

    const initialWithdrawalRequest = new Withdrawal.InitiateWithdrawalRequest();
    initialWithdrawalRequest.setFromaccountid(accountID);
    initialWithdrawalRequest.setDestinationaddress(destination);
    initialWithdrawalRequest.setAmount(amount);
    const initialWithdrawalResponse = await unary(
      WithdrawalService.Withdrawal.InitiateWithdrawal,
      initialWithdrawalRequest,
      jwt,
    );

    const challengeRequest = requireValue(initialWithdrawalResponse.getChallengerequest());
    const processWithdrawRequest = new Withdrawal.ProcessWithdrawalRequest();
    const credentialRequest = requireValue(initialWithdrawalResponse.getCredentialrequest());
    const assertion = await Webauthn.requestAssertion(challengeRequest, credentialRequest);
    processWithdrawRequest.setAssertion(assertion);
    processWithdrawRequest.setId(initialWithdrawalResponse.getId());

    const processWithdrawResponse = await unary(
      WithdrawalService.Withdrawal.ProcessWithdrawal,
      processWithdrawRequest,
      jwt,
    );
    return processWithdrawResponse;
  },
);

export const makeDepositFromFaucet = createAsyncThunk(
  'transact/depositFromFaucet',
  async (args: makeFaucetReqParam) => {
    const { currency, address, jwt } = args;
    const faucetRequest = new Deposit.DepositFromFaucetRequest();
    faucetRequest.setCurrency(currency);
    faucetRequest.setAddress(address);
    const depositFromFaucet = await unary(
      DepositService.Deposit.DepositFromFaucet,
      faucetRequest,
      jwt,
    );
    return depositFromFaucet;
  },
);

export const makeTransactionsSlice = createSlice({
  name: 'transact',
  initialState,
  reducers: {
  },
  extraReducers: (builder) => {
    builder.addCase(makeDepositKey.fulfilled, (state, action) => {
      state.depositKeys.push(action.payload as RevealedDepositKey);
    });
    builder.addCase(listDepositKeys.fulfilled, (state, action) => {
      state.depositKeys = action.payload;
    });
  },
});

export default makeTransactionsSlice.reducer;
