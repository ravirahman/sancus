import React from 'react';
import { TransactionResponse } from 'protobufs/institution/account_pb';
import {
  Box,
  Typography,
  Grid,
  makeStyles,
  Tooltip,
} from '@material-ui/core';
import { Timestamp } from 'google-protobuf/google/protobuf/timestamp_pb';
import { Decimal } from 'decimal.js';

type TransactionProps = {
  transaction: TransactionResponse,
  currency: string,
};

const useStyles = makeStyles({
  pending: {
    fontStyle: 'italic',
    color: 'gray',
  },
});

const transactionTypeMap: Map<0 | 1 | 2 | 3, string> = new Map([
  [0, 'Invalid Transaction'],
  [1, 'Deposit'],
  [2, 'Exchange'],
  [3, 'Withdraw'],
]);

const statusTypeMap: Map<0 | 1 | 2 | 3, string> = new Map([
  [0, 'Invalid Status'],
  [1, 'Pending'],
  [2, 'Completed'],
  [3, 'Cancelled'],
]);

const TransactionBox = (props: TransactionProps) => {
  const { transaction, currency } = props;

  const id = transaction.getId_asB64();
  const status = statusTypeMap.get(transaction.getStatus());
  const protobufTimestamp = transaction.getTimestamp() as Timestamp;
  const time = protobufTimestamp.toDate().toString();
  const type = transactionTypeMap.get(transaction.getTransactiontype());
  const amount = transaction.getAmount();

  const deciAmount = new Decimal(amount);
  const truncAmount = deciAmount.precision() < 6 ? deciAmount.toString() : deciAmount.toPrecision(6);

  const classes = useStyles();
  return (
    <Box>
      <Grid container justify="space-between" spacing={3}>
        <Grid item xs={9}>
          <Box m={1}>
            <Typography variant="h6">{type}</Typography>
            <Typography>{id}</Typography>
            <Typography className={classes.pending}>{time}</Typography>
          </Box>
        </Grid>
        <Grid item>
          <Box m={1}>
            <Tooltip title={amount} placement="top">
              <Typography align="right" variant="h6">{`${truncAmount} ${currency}`}</Typography>
            </Tooltip>
            <Typography align="right" className={classes.pending}>{status}</Typography>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default TransactionBox;
