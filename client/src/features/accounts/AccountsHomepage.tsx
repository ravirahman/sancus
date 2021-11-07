import React from 'react';
import { Grid, Typography, Box } from '@material-ui/core';

import AccountsContainer from './AccountsContainer';
import { useAppSelector } from '../../app/hooks';
import TransactionsContainer from './TransactionsContainer';

const AccountsHomepage = () => {
  const selectedTransactions = useAppSelector((state) => {
    return state.accounts.transactions;
  });
  const selectedAccData = useAppSelector((state) => {
    return state.accounts.selectedAccountData;
  });

  const transactionsInfo = selectedAccData ? (
    <TransactionsContainer
      transactions={selectedTransactions}
      currency={selectedAccData.currency}
    />
  ) : <></>;

  return (
    <Grid container>
      <Grid item xs={12} md={6}>
        <Box p={2}>
          <Typography variant="h4" align="center">Accounts</Typography>
          <AccountsContainer />
        </Box>
      </Grid>
      <Grid item xs={12} md={6}>
        {transactionsInfo}
      </Grid>
    </Grid>
  );
};

export default AccountsHomepage;
