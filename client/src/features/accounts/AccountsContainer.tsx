import React, { useEffect } from 'react';
import { Box, Paper, Typography } from '@material-ui/core';

import { useAppSelector, useAppDispatch } from '../../app/hooks';
import {
  getAccounts,
  getTransactions,
  setSelectedAccount,
  setSelectedAccountData,
} from './accountsSlice';

import AccountInfoBox from './AccountInfoBox';
import TransactionsContainer from './TransactionsContainer';

const AccountsContainer = () => {
  const jwt = useAppSelector((state) => {
    return state.auth.jwt;
  });
  const accountsInfo = useAppSelector((state) => {
    return state.accounts.accounts;
  });
  const selectedAccount = useAppSelector((state) => {
    return state.accounts.selectedAccount;
  });
  const selectedTransactions = useAppSelector((state) => {
    return state.accounts.transactions;
  });
  const selectedAccData = useAppSelector((state) => {
    return state.accounts.selectedAccountData;
  });

  const dispatch = useAppDispatch();

  const selectAcc = (bytesId: Uint8Array, currency: string, available: string) => {
    dispatch(setSelectedAccount(bytesId));
    dispatch(setSelectedAccountData({ currency, available }));
  };

  const updateAccounts = () => {
    if (jwt) {
      dispatch(getAccounts(jwt));
    }
  };

  useEffect(() => {
    updateAccounts();
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      updateAccounts();
    }, 2500);
    return () => {
      return clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (selectedAccount && jwt) {
      const getTransArgs = {
        accountID: selectedAccount,
        jwt,
      };
      dispatch(getTransactions(getTransArgs));
    }
  }, [selectedAccData]);

  const transactionsContainer = !selectedTransactions || !selectedAccData ? <></> : (
    <TransactionsContainer
      transactions={selectedTransactions}
      currency={selectedAccData.currency}
    />
  );

  const accountInfoBoxes = accountsInfo ? accountsInfo.map((acc) => {
    const bytesId = acc.getId_asU8();
    const id = acc.getId_asB64();
    return (
      <AccountInfoBox
        id={id}
        bytesId={bytesId}
        selectAcc={selectAcc}
        accountType={acc.getAccounttype()}
        currency={acc.getCurrency()}
        available={acc.getAvailableamount()}
        pending={acc.getPendingamount()}
        key={id}
      />
    );
  }) : <Typography variant="h5" align="center">No Accounts</Typography>;

  return (
    <Paper>
      <Box p={1}>
        {accountInfoBoxes}
      </Box>
      {transactionsContainer}
    </Paper>
  );
};

export default AccountsContainer;
