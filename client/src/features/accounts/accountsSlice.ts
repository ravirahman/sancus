import {
  createAsyncThunk, createSlice, PayloadAction,
} from '@reduxjs/toolkit';
import { AccountResponse, TransactionResponse } from 'protobufs/institution/account_pb';
import { Timestamp } from 'google-protobuf/google/protobuf/timestamp_pb';
import * as Account from 'protobufs/institution/account_pb';
import * as AccountService from 'protobufs/institution/account_pb_service';

import { unary } from '../../utils/grpcClient';

type SelectedAccountData = {
  currency: string,
  available: string,
};

type SliceState = {
  accounts: AccountResponse[] | undefined,
  selectedAccount: Uint8Array | undefined;
  transactions: TransactionResponse[] | undefined;
  selectedAccountData: SelectedAccountData | undefined,
};

type GetTransactionsParams = {
  accountID: Uint8Array,
  jwt: string,
}

const initialState: SliceState = {
  accounts: undefined,
  transactions: undefined,
  selectedAccount: undefined,
  selectedAccountData: undefined,
};

export const getAccounts = createAsyncThunk(
  'accounts/getAccounts',
  async (jwt: string) => {
    const listAccountsRequest = new Account.ListAccountsRequest();
    const request = new Account.ListAccountsRequest.Request();
    listAccountsRequest.setRequest(request);
    const listAccountsResponse = await unary(
      AccountService.Account.ListAccounts,
      listAccountsRequest,
      jwt,
    );
    const respList = listAccountsResponse.getResponseList();
    let nextToken = listAccountsResponse.getNexttoken();
    /* eslint-disable no-await-in-loop */
    while (nextToken) {
      const nextAccountsRequest = new Account.ListAccountsRequest();
      nextAccountsRequest.setNexttoken(nextToken);
      const nextResponse = await unary(
        AccountService.Account.ListAccounts,
        nextAccountsRequest,
        jwt,
      );
      nextToken = nextResponse.getNexttoken();
      respList.push(...nextResponse.getResponseList());
    }
    return respList;
  },
);

export const getTransactions = createAsyncThunk(
  'accounts/getTransactions',
  async ({ accountID, jwt }: GetTransactionsParams) => {
    const listTransactionsRequest = new Account.ListTransactionsRequest();
    const request = new Account.ListTransactionsRequest.Request();
    request.setAccountid(accountID);

    const zeroTimestamp = new Timestamp();
    const nowTimestamp = new Timestamp();
    zeroTimestamp.fromDate(new Date(0));
    nowTimestamp.fromDate(new Date());

    request.setFromtimestamp(zeroTimestamp);
    request.setTotimestamp(nowTimestamp);
    listTransactionsRequest.setRequest(request);
    const listTransactionsResponse = await unary(
      AccountService.Account.ListTransactions,
      listTransactionsRequest,
      jwt,
    );
    const respList = listTransactionsResponse.getResponseList();
    let nextToken = listTransactionsResponse.getNexttoken();
    // TODO don't use while loop, there may be many many transactions in future
    /* eslint-disable no-await-in-loop */
    while (nextToken) {
      const nextTransactionsRequest = new Account.ListTransactionsRequest();
      nextTransactionsRequest.setNexttoken(nextToken);
      const nextResponse = await unary(
        AccountService.Account.ListTransactions,
        nextTransactionsRequest,
        jwt,
      );
      nextToken = nextResponse.getNexttoken();
      respList.push(...nextResponse.getResponseList());
    }
    return respList;
  },
);

export const accountsSlice = createSlice({
  name: 'accounts',
  initialState,
  reducers: {
    setSelectedAccount: (state, action: PayloadAction<Uint8Array>) => {
      state.selectedAccount = action.payload;
    },
    setSelectedAccountData: (state, action: PayloadAction<SelectedAccountData>) => {
      state.selectedAccountData = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(getAccounts.fulfilled, (state, action) => {
      state.accounts = action.payload;
      if (state.selectedAccount) {
        const selectedAccRes = state.accounts.find((a) => {
          return JSON.stringify(a.getId_asU8()) === JSON.stringify(state.selectedAccount);
        });
        if (selectedAccRes) {
          state.selectedAccountData = {
            currency: selectedAccRes.getCurrency(),
            available: selectedAccRes.getAvailableamount(),
          };
        }
      }
      if (!state.selectedAccount && action.payload.length) {
        const firstAcc = action.payload[0];
        state.selectedAccount = firstAcc.getId_asU8();
        state.selectedAccountData = {
          currency: firstAcc.getCurrency(),
          available: firstAcc.getAvailableamount(),
        };
      }
    });
    builder.addCase(getTransactions.fulfilled, (state, action) => {
      state.transactions = action.payload;
    });
  },
});

export const { setSelectedAccount, setSelectedAccountData } = accountsSlice.actions;

export default accountsSlice.reducer;
