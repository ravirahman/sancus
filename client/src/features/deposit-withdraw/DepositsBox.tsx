import React, { useState, useEffect } from 'react';

import {
  Box,
  TextField,
  FormControl,
  FormLabel,
  Radio,
  RadioGroup,
  FormControlLabel,
  Button,
  Grid,
  Typography,
  Paper,
  makeStyles,
} from '@material-ui/core';
import FileCopyOutlinedIcon from '@material-ui/icons/FileCopyOutlined';
import QRCode from 'qrcode.react';

import { useAppSelector, useAppDispatch } from '../../app/hooks';
import { makeDepositFromFaucet } from './makeTransactionsSlice';
import requireValue from '../../utils/requireValue';
import { showFaucet } from '../../app/config';

const useStyles = makeStyles(() => {
  return ({
    root: {
      padding: '2px 4px',
      display: 'flex',
      alignItems: 'center',
    },
    copyButton: {
      padding: 8,
    },
  });
});

const DepositsBox = () => {
  const classes = useStyles();

  const dispatch = useAppDispatch();

  const selectedAccData = useAppSelector((state) => {
    return state.accounts.selectedAccountData;
  });

  const jwt = useAppSelector((state) => {
    return state.auth.jwt;
  });

  const [selectedKey, setSelectedKey] = useState<string | undefined>(undefined);

  const depositKeys = useAppSelector((state) => {
    return state.transact.depositKeys;
  });

  const keys = depositKeys.map((revealedKey) => {
    return revealedKey.getAddress();
  });

  useEffect(() => {
    if (keys.length) {
      setSelectedKey(keys[0]);
    }
    else {
      setSelectedKey(undefined);
    }
  }, [depositKeys]);

  const keysAsRadioButtons = keys.map((keyVal) => {
    return (
      <FormControlLabel value={keyVal} control={<Radio />} label={keyVal} />
    );
  });

  const keysRadioGroup = (
    <FormControl component="fieldset">
      <FormLabel component="legend">Select a Deposit Key</FormLabel>
      <RadioGroup
        key={selectedKey}
        value={selectedKey}
        onChange={(e) => {
          setSelectedKey(e.target.value);
        }}
      >
        {keysAsRadioButtons}
      </RadioGroup>
    </FormControl>
  );

  const noKeysMessage = (
    <Typography>No Deposit Keys Found. Please Create A New Deposit Key Below</Typography>
  );

  const copyButton = (
    <Button
      className={classes.copyButton}
      variant="contained"
      color="primary"
      onClick={() => {
        navigator.clipboard.writeText(requireValue(selectedKey));
      }}
    >
      <FileCopyOutlinedIcon />
    </Button>
  );

  const depositKeyQRCode = selectedKey ? (
    <QRCode
      size={200}
      value={selectedKey}
    />
  ) : <Typography>No Deposit Key Selected</Typography>;

  const depositDetails = selectedAccData ? (
    <Typography>{`Send ${selectedAccData.currency} to the address above or in the QR code.`}</Typography>
  ) : (
    <Typography>No Account Selected</Typography>
  );

  const handleFaucetDeposit = () => {
    if (jwt && selectedKey && selectedAccData) {
      dispatch(makeDepositFromFaucet({ jwt, currency: selectedAccData.currency, address: selectedKey }));
    }
  };

  const faucetButton = showFaucet ? (
    <Button
      onClick={handleFaucetDeposit}
      variant="contained"
      disabled={!selectedKey || !selectedAccData}
    >
      Deposit From Faucet
    </Button>
  ) : <></>;

  return (
    <Paper>
      <Box p={2}>
        <Grid container>
          <Grid item sm={4}>
            <Box p={1}>
              {depositKeyQRCode}
            </Box>
          </Grid>
          <Grid item sm={8}>
            {keys.length ? keysRadioGroup : noKeysMessage}
            <Paper elevation={0} className={classes.root}>
              <TextField
                key={selectedKey}
                style={{ width: '100%' }}
                value={selectedKey}
                variant="outlined"
                margin="dense"
              />
              {copyButton}
            </Paper>
            {depositDetails}
            {faucetButton}
          </Grid>
        </Grid>
      </Box>
    </Paper>
  );
};

export default DepositsBox;
