import React from 'react';
import { connect } from 'react-redux';
import { Link as RouterLink, RouteComponentProps, withRouter } from 'react-router-dom';
import {
  AppBar,
  Button,
  Link,
  Grid,
  Typography,
  makeStyles,
} from '@material-ui/core';
import { RootState } from '../../app/reducer';

const useStyles = makeStyles({
  headBar: {
    padding: '10px 20px 0px 20px',
  },
  title: {
    fontFamily: ['Newsreader', 'serif'].join(','),
  },
  buttons: {
    margin: '4px',
    borderWidth: '2px',
  },
});

const mapStateToProps = (state: RootState) => {
  return {
    isLoggedIn: state.auth.jwt !== undefined,
  };
};

type NavigationProps = ReturnType<typeof mapStateToProps> & RouteComponentProps;

const Navigation = (props: NavigationProps) => {
  const classes = useStyles();

  const accessibilityButton = (
    <a href="https://accessibility.mit.edu/" target="_blank" rel="noopener noreferrer">
      <Button className={classes.buttons}>
        Accessibility
      </Button>
    </a>
  );

  const authenticatedNav = (
    <AppBar position="static" className={classes.headBar}>
      <Grid container justify="space-between">
        <Grid item>
          <Typography variant="h2" className={classes.title}>Sancus</Typography>
        </Grid>
        <Grid item>
          {accessibilityButton}
          <Link component={RouterLink} to="/">
            <Button className={classes.buttons} size="large" variant="outlined">
              Transaction History
            </Button>
          </Link>
          <Link component={RouterLink} to="/deposit-withdraw">
            <Button className={classes.buttons} size="large" variant="outlined">
              Deposit / Withdraw
            </Button>
          </Link>
          <Link component={RouterLink} to="/exchange">
            <Button className={classes.buttons} size="large" variant="outlined">
              Exchange
            </Button>
          </Link>
          <Link component={RouterLink} to="/auth/logout">
            <Button className={classes.buttons} size="large" variant="outlined">
              Logout
            </Button>
          </Link>
        </Grid>
      </Grid>
    </AppBar>
  );

  const unauthenticatedNav = (
    <AppBar position="static" className={classes.headBar}>
      <Grid container justify="space-between">
        <Grid item>
          <Typography variant="h2" className={classes.title}>Sancus</Typography>
        </Grid>
        <Grid item>
          {accessibilityButton}
          <Link component={RouterLink} to="/auth">
            <Button className={classes.buttons} size="large" variant="contained">
              Login
            </Button>
          </Link>
        </Grid>
      </Grid>
    </AppBar>
  );
  const nav = props.isLoggedIn ? authenticatedNav : unauthenticatedNav;
  return nav;
};

export default connect(mapStateToProps)(withRouter(Navigation));
