import React from 'react';
import {
  BrowserRouter as Router, Route, Switch,
} from 'react-router-dom';
import { connect } from 'react-redux';
import { Box } from '@material-ui/core';

import Auth from '../features/auth/Auth';
import PrivateRoute from '../utils/PrivateRoute';
import { RootState } from './reducer';
import Navigation from '../features/navigation/Navigation';
import AccountsHomepage from '../features/accounts/AccountsHomepage';
import DepositAndWithdraw from '../features/deposit-withdraw/DepositAndWithdraw';
import Exchange from '../features/exchange/Exchange';

const mapStateToProps = (state: RootState) => {
  return {
    isLoggedIn: state.auth.jwt !== undefined,
  };
};

const App = () => {
  return (
    <Router>
      <Navigation />
      <Box m={2}>
        <Switch>
          <Route path="/auth">
            <Auth />
          </Route>
          <PrivateRoute path="/exchange">
            <Exchange />
          </PrivateRoute>
          <PrivateRoute path="/deposit-withdraw">
            <DepositAndWithdraw />
          </PrivateRoute>
          <PrivateRoute path="/">
            <AccountsHomepage />
          </PrivateRoute>
        </Switch>
      </Box>
    </Router>
  );
};

export default connect(mapStateToProps)(App);
