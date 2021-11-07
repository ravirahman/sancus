import React from 'react';
import {
  Box,
  List,
  Typography,
  Divider,
} from '@material-ui/core';
import { TransactionResponse } from 'protobufs/institution/account_pb';
import TransactionBox from './TransactionBox';

type TransactionsContainerProps = {
  transactions: TransactionResponse[] | undefined,
  currency: string,
};

const TransactionsContainer = (props: TransactionsContainerProps) => {
  const { transactions, currency } = props;

  const noTransactionsMsg = <Typography variant="h6" align="center">No transactions yet!</Typography>;

  const transactionsBoxes = transactions && transactions.length ? transactions.map((t) => {
    return (
      <>
        <TransactionBox transaction={t} currency={currency} />
        <Divider component="li" />
      </>
    );
  }) : noTransactionsMsg;

  return (
    <Box>
      <Typography align="center" variant="h5">Transactions</Typography>
      <List>
        <Divider component="li" />
        {transactionsBoxes}
      </List>
    </Box>
  );
};

export default TransactionsContainer;
