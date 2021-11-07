import { combineReducers } from '@reduxjs/toolkit';

import authReducer from '../features/auth/slice';
import accountsReducer from '../features/accounts/accountsSlice';
import makeTransactionsReducer from '../features/deposit-withdraw/makeTransactionsSlice';
import exchangeSliceReducer from '../features/exchange/exchangeSlice';

const rootReducer = combineReducers({
  auth: authReducer,
  accounts: accountsReducer,
  transact: makeTransactionsReducer,
  exchange: exchangeSliceReducer,
});

export type RootState = ReturnType<typeof rootReducer>;
export default rootReducer;
