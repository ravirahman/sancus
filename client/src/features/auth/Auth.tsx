import React, { useState } from 'react';
import {
  RouteComponentProps,
  withRouter,
  Switch,
} from 'react-router-dom';
import { Location } from 'history';
import { connect } from 'react-redux';
import { SerializedError } from '@reduxjs/toolkit';
import { toast } from 'react-toastify';
import {
  Grid,
  Box,
  Paper,
  TextField,
  Typography,
  Button,
} from '@material-ui/core';

import { mapDispatchToProps } from './slice';
import { LocationState } from '../../utils/PrivateRoute';
import PublicRoute from '../../utils/PublicRoute';

interface Props extends ReturnType<typeof mapDispatchToProps>, RouteComponentProps {
  location: Location<LocationState>
}

const authErrMsg = 'authentication failed: You may be missing the required hardware or credentials.';

const Auth = (props: Props) => {
  const { logout } = props;
  const [username, setUsername] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  if (props.location.pathname === '/auth/logout') {
    logout();
    window.location.href = '/';
  }

  const navigate = () => {
    const { location, history } = props;
    let pathname = '/';
    if (location.state) {
      const { from } = location.state;
      if (from.pathname !== '/auth/logout') {
        pathname = from.pathname;
      }
    }
    history.replace({
      pathname,
    });
  };

  const register = async (): Promise<void> => {
    try {
      setIsLoading(true);
      await props.register(username);
    }
    catch (err: unknown) {
      setIsLoading(false);
      const serializedErr = err as SerializedError;
      const errMsg = serializedErr.name === 'NotAllowedError' ? `Registration ${authErrMsg}` : serializedErr.message;
      toast.error(errMsg, {
        position: 'top-right',
        autoClose: false,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
      });
      return;
    }
    navigate();
  };

  const login = async (): Promise<void> => {
    try {
      setIsLoading(true);
      await props.login(username);
    }
    catch (err: unknown) {
      setIsLoading(false);
      const serializedErr = err as SerializedError;
      const errMsg = serializedErr.name === 'NotAllowedError' ? `Login ${authErrMsg}` : serializedErr.message;
      toast.error(errMsg, {
        position: 'top-right',
        autoClose: false,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
      });
      return;
    }
    navigate();
  };

  const handleUsernameInputOnChange = (event: React.ChangeEvent<HTMLInputElement>): void => {
    setUsername(event.target.value);
  };

  const { match } = props;
  return (
    <Switch>
      <PublicRoute exact path={match.path}>
        <Grid
          container
          direction="column"
          alignItems="center"
          justify="center"
        >
          <Grid item xs={12} sm={8} md={6} lg={4}>
            <Paper elevation={2}>
              <Box p={5} mt={5}>
                <Typography align="center" variant="h2">Sign In</Typography>
                <TextField
                  variant="outlined"
                  required
                  fullWidth
                  id="username"
                  label="Username"
                  autoFocus
                  value={username}
                  onChange={handleUsernameInputOnChange}
                />
                <Box m={2}>
                  <Button variant="contained" onClick={register} value="Register" disabled={isLoading}>
                    Register
                  </Button>
                  <Button variant="contained" onClick={login} value="Login" disabled={isLoading}>
                    Login
                  </Button>
                </Box>
              </Box>
            </Paper>
          </Grid>
        </Grid>
      </PublicRoute>
    </Switch>
  );
};

export default connect(null, mapDispatchToProps)(withRouter(Auth));
