import React, { useEffect } from 'react';
import {
  Grid,
  Box,
  Typography,
  Button,
} from '@material-ui/core';
import { SerializedError } from '@reduxjs/toolkit';
import { toast } from 'react-toastify';
// import * as publicKeyToAddress from 'ethereum-public-key-to-address';

import AccountsContainer from '../accounts/AccountsContainer';
import { useAppSelector, useAppDispatch } from '../../app/hooks';
import { makeDepositKey, listDepositKeys } from './makeTransactionsSlice';
import DepositsBox from './DepositsBox';
import WithdrawsBox from './WithdrawsBox';

const DepositAndWithdraw = () => {
  const dispatch = useAppDispatch();

  const jwt = useAppSelector((state) => {
    return state.auth.jwt;
  });
  const selectedAccount = useAppSelector((state) => {
    return state.accounts.selectedAccount;
  });

  useEffect(() => {
    try {
      if (selectedAccount && jwt) {
        dispatch(listDepositKeys({ accountID: selectedAccount, jwt }));
      }
    }
    catch (err: unknown) {
      const serializedErr = err as SerializedError;
      const errMsg = serializedErr.message;
      toast.error(errMsg, {
        position: 'top-right',
        autoClose: false,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
      });
    }
  }, [selectedAccount]);

  const makeNewKey = () => {
    if (selectedAccount && jwt) {
      dispatch(makeDepositKey({ accountID: selectedAccount, jwt }));
    }
  };

  return (
    <Grid container>
      <Grid item xs={12} md={6}>
        <Box p={2}>
          <Typography variant="h4" align="center">Choose an Account:</Typography>
          <AccountsContainer />
        </Box>
      </Grid>
      <Grid item xs={12} md={6}>
        <Box p={2}>
          <Grid container justify="space-between">
            <Grid item>
              <Typography variant="h3">Deposit Keys:</Typography>
            </Grid>
            <Grid item>
              <Button variant="contained" color="secondary" size="large" onClick={makeNewKey}>Add Deposit Key</Button>
              <Button variant="contained" color="primary" size="large">Verify Deposits</Button>
            </Grid>
          </Grid>
          <DepositsBox />
        </Box>
        <Box p={2}>
          <Typography variant="h3">Withdraw</Typography>
          <WithdrawsBox />
        </Box>
      </Grid>
    </Grid>
  );
};

export default DepositAndWithdraw;
