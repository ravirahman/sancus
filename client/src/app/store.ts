import { configureStore, getDefaultMiddleware } from '@reduxjs/toolkit';
import {
  persistStore, persistReducer, FLUSH,
  REHYDRATE,
  PAUSE,
  PERSIST,
  PURGE,
  REGISTER,
} from 'redux-persist';
import storage from 'redux-persist/lib/storage';

import rootReducer from './reducer';

const persistConfig = {
  key: 'root',
  storage,
  whitelist: ['auth'], // only want the jwt persisted to storage
};

const persistedReducer = persistReducer(persistConfig, rootReducer);

const store = configureStore({
  reducer: persistedReducer,
  middleware: getDefaultMiddleware({
    serializableCheck: {
      ignoredActions: [FLUSH, REHYDRATE, PAUSE, PERSIST, PURGE, REGISTER],
    },
  }),
});

export default store;
export const persistor = persistStore(store);
export type AppDispatch = typeof store.dispatch;
