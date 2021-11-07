import React from 'react';
import {
  Box,
  Grid,
  Typography,
  makeStyles,
  Button,
  Tooltip,
} from '@material-ui/core';
import { Decimal } from 'decimal.js';

const useStyles = makeStyles({
  pending: {
    fontStyle: 'italic',
    color: 'gray',
  },
});

type AccountInfoBoxProps = {
  id: string,
  bytesId: Uint8Array,
  accountType: 0 | 1 | 2 | 3,
  currency: string,
  available: string,
  pending: string,
  selectAcc: (bytesId: Uint8Array, currency: string, available: string) => void,
};

const currencyMap: Map<string, string> = new Map([
  ['BTC', 'Bitcoin'],
  ['ETH', 'Ethereum'],
  ['GUSD', 'Gemini USD'],
]);

const accountTypeMap: Map<0 | 1 | 2 | 3, string> = new Map([
  [0, 'Invalid Account'],
  [1, 'Deposit Account'],
  [2, 'Loan Account'],
  [3, 'Collateral Account'],
]);

const AccountInfoBox = (props: AccountInfoBoxProps) => {
  const {
    id,
    bytesId,
    accountType,
    currency,
    available,
    pending,
    selectAcc,
  } = props;

  const classes = useStyles();

  const handleSelect = () => {
    selectAcc(bytesId, currency, available);
  };

  const deciAvailable = new Decimal(available);
  const deciPending = new Decimal(pending);
  const truncAvailable = deciAvailable.precision() < 6 ? deciAvailable.toString() : deciAvailable.toPrecision(6);
  const truncPending = deciPending.precision() < 6 ? deciPending.toString() : deciPending.toPrecision(6);

  return (
    <Box bgcolor="#D3D3D3" m={1} py={1} px={2} borderRadius={10}>
      <Typography variant="h5">{currencyMap.get(currency)}</Typography>
      <Grid container>
        <Grid item xs={8}>
          <Typography variant="body2">{id}</Typography>
          <Typography>{accountTypeMap.get(accountType)}</Typography>
        </Grid>
        <Grid item xs={4}>
          <Tooltip title={available} placement="top-end">
            <Typography variant="h5" align="right">{`${truncAvailable} ${currency}`}</Typography>
          </Tooltip>
          <Tooltip title={pending} placement="top-end">
            <Typography variant="body2" className={classes.pending} align="right">
              {`Pending: ${truncPending} ${currency}`}
            </Typography>
          </Tooltip>
        </Grid>
      </Grid>
      <Button variant="outlined" onClick={handleSelect}>
        Select This Account
      </Button>
    </Box>
  );
};

export default AccountInfoBox;
