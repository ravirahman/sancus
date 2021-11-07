import React, { useState } from 'react';

import {
  Box,
  TextField,
  Paper,
  Button,
  Grid,
  Typography,
  Tooltip,
} from '@material-ui/core';
import { toast } from 'react-toastify';
import { SerializedError } from '@reduxjs/toolkit';
import { Decimal } from 'decimal.js';

import { useAppSelector, useAppDispatch } from '../../app/hooks';
import { makeWithdrawal } from './makeTransactionsSlice';

const WithdrawsBox = () => {
  const selectedAccData = useAppSelector((state) => {
    return state.accounts.selectedAccountData;
  });

  const jwt = useAppSelector((state) => {
    return state.auth.jwt as string;
  });

  const selectedAccount = useAppSelector((state) => {
    return state.accounts.selectedAccount;
  });

  const dispatch = useAppDispatch();

  const [address, setAddress] = useState('');
  const [sendAmount, setSendAmount] = useState('0');

  const handleWithdraw = async (): Promise<void> => {
    const withdrawParamObj = {
      jwt,
      accountID: selectedAccount as Uint8Array,
      destination: address,
      amount: sendAmount,
    };

    try {
      await dispatch(makeWithdrawal(withdrawParamObj));
    }
    catch (err: unknown) {
      const serializedErr = err as SerializedError;
      toast.error(serializedErr, {
        position: 'top-right',
        autoClose: false,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
      });
    }
  };

  let withdrawalDetails = <Button disabled>Withdraw</Button>;

  if (selectedAccData) {
    const { available, currency } = selectedAccData;
    const deciAvailable = new Decimal(available);
    const truncAvailable = deciAvailable.precision() < 6 ? deciAvailable.toString() : deciAvailable.toPrecision(6);
    withdrawalDetails = (
      <>
        <Button variant="contained" color="secondary" disabled={!address} onClick={handleWithdraw}>
          {`Send ${sendAmount} ${currency} to ${address}`}
        </Button>
        <Tooltip title={available}>
          <Typography>{`You have ${truncAvailable} ${currency} available for withdraw`}</Typography>
        </Tooltip>
      </>
    );
  }

  return (
    <Paper>
      <Box p={3}>
        <Grid container>
          <Grid item md={8}>
            <Box p={1}>
              <TextField
                id="destination-address"
                label="Address"
                style={{ width: '100%' }}
                value={address}
                onChange={(e) => {
                  setAddress(e.target.value);
                }}
                variant="outlined"
              />
            </Box>
            <Box p={1}>
              <TextField
                id="amount-withdraw"
                label="Amount"
                style={{ width: '100%' }}
                value={sendAmount}
                onChange={(e) => {
                  setSendAmount(e.target.value);
                }}
                variant="outlined"
              />
            </Box>
            {withdrawalDetails}
          </Grid>
        </Grid>
      </Box>
    </Paper>
  );
};

export default WithdrawsBox;
