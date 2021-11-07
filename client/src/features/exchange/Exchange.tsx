import React, { useEffect, useState } from 'react';
import {
  Grid,
  Paper,
  Typography,
  Box,
  TextField,
  Button,
  InputAdornment,
} from '@material-ui/core';
import { Decimal } from 'decimal.js';

import AccountChooser from './AccountChooser';
import { useAppDispatch, useAppSelector } from '../../app/hooks';
import ExpirationCountdown from './ExpirationCountdown';
import {
  setFromAccount,
  setToAccount,
  makeExchange,
  getExchangeRate,
} from './exchangeSlice';
import { getAccounts } from '../accounts/accountsSlice';

const Exchange = () => {
  const selectedFromAccount = useAppSelector((state) => {
    return state.exchange.fromAccount;
  });
  const selectedToAccount = useAppSelector((state) => {
    return state.exchange.toAccount;
  });
  const jwt = useAppSelector((state) => {
    return state.auth.jwt;
  });
  const exchangeRateJWT = useAppSelector((state) => {
    return state.exchange.exchangeRateJWT;
  });
  const rate = useAppSelector((state) => {
    return state.exchange.rate;
  });
  const expiration = useAppSelector((state) => {
    return state.exchange.expiration;
  });

  const fromCurrency = selectedFromAccount ? selectedFromAccount.currency : null;
  const toCurrency = selectedToAccount ? selectedToAccount.currency : null;

  const [recieveAmount, setRecieveAmount] = useState('0');
  const [sendAmount, setSendAmount] = useState('0');

  const dispatch = useAppDispatch();

  const selectFromAcc = (bytesId: Uint8Array, currency: string, available: string) => {
    dispatch(setFromAccount({ bytesId, currency, available }));
  };
  const selectToAcc = (bytesId: Uint8Array, currency: string, available: string) => {
    dispatch(setToAccount({ bytesId, currency, available }));
  };

  const handleExchange = async (): Promise<void> => {
    if (exchangeRateJWT && jwt && selectedFromAccount && selectedToAccount) {
      const exchangeParamObj = {
        jwt,
        fromAccount: selectedFromAccount,
        toAccount: selectedToAccount,
        amount: recieveAmount,
        exchangeRateJWT,
      };
      await dispatch(makeExchange(exchangeParamObj));
      dispatch(getAccounts(jwt));
      // window.location.reload();
    }
  };

  const updateExchangeRate = () => {
    if (selectedToAccount && selectedFromAccount && jwt) {
      const getExchangeRateArgs = {
        from: selectedFromAccount.currency,
        to: selectedToAccount.currency,
        jwt,
      };
      dispatch(getExchangeRate(getExchangeRateArgs));
    }
  };

  useEffect(() => {
    if (jwt) {
      dispatch(getAccounts(jwt));
    }
  }, []);

  useEffect(() => {
    updateExchangeRate();
  }, [selectedFromAccount, selectedToAccount]);

  const updateRate = () => {
    updateExchangeRate();
    if (rate) {
      setRecieveAmount(String(Number(sendAmount) / rate));
    }
  };

  const disableExchange = !(selectedFromAccount && selectedToAccount);

  let exchangeInfoBox = (
    <Box m={1}>
      <Typography>Choose the currencies you want to exchange between</Typography>
    </Box>
  );

  if (selectedFromAccount && selectedToAccount && expiration) {
    const deciAvailable = new Decimal(selectedFromAccount.available);
    const truncAvailable = deciAvailable.precision() < 6 ? deciAvailable.toString() : deciAvailable.toPrecision(6);
    exchangeInfoBox = (
      <Box m={1}>
        <Typography>{`Exchange Rate: ${rate} ${fromCurrency}/${toCurrency}`}</Typography>
        <Typography>
          {`You have ${truncAvailable} ${selectedFromAccount.currency} available for exchange`}
        </Typography>
        <ExpirationCountdown updateRate={updateRate} expiration={expiration} />
        <Typography>{`Rate valid until ${expiration?.toString()}`}</Typography>
      </Box>
    );
  }

  return (
    <Grid container spacing={3}>
      <Grid item xs={12} md={4}>
        <Paper>
          <Box p={2}>
            <Typography variant="h4" align="center">Account to Transfer From</Typography>
            <AccountChooser omit="" selection={selectFromAcc} />
          </Box>
        </Paper>
      </Grid>
      <Grid item xs={12} md={4}>
        <Paper>
          <Box p={2}>
            <Typography variant="h4" align="center">Account to Transfer To</Typography>
            <AccountChooser omit={fromCurrency} selection={selectToAcc} />
          </Box>
        </Paper>
      </Grid>
      <Grid item xs={12} md={4}>
        <Paper>
          <Box p={2}>
            <Typography variant="h4" align="center">Exchange Details</Typography>
            <Typography variant="h5">From Account</Typography>
            <TextField
              label="Amount"
              style={{ width: '100%' }}
              value={sendAmount}
              disabled={disableExchange}
              onChange={(e) => {
                if (rate) {
                  setSendAmount(e.target.value);
                  setRecieveAmount(String(parseFloat(e.target.value) / rate));
                }
              }}
              InputProps={{
                endAdornment: <InputAdornment position="end">{fromCurrency}</InputAdornment>,
              }}
              variant="outlined"
            />
            <Typography variant="h5">To Account</Typography>
            <TextField
              label="Amount"
              style={{ width: '100%' }}
              value={recieveAmount}
              disabled={disableExchange}
              onChange={(e) => {
                if (rate) {
                  setRecieveAmount(e.target.value);
                  setSendAmount(String(rate * parseFloat(e.target.value)));
                }
              }}
              InputProps={{
                endAdornment: <InputAdornment position="end">{toCurrency}</InputAdornment>,
              }}
              variant="outlined"
            />
            {exchangeInfoBox}
            <Button
              variant="contained"
              size="large"
              color="secondary"
              disabled={disableExchange}
              onClick={handleExchange}
            >
              Confirm Exchange
            </Button>
          </Box>
        </Paper>
      </Grid>
    </Grid>
  );
};

export default Exchange;
