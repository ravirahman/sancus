import React from 'react';

import { Route, Redirect } from 'react-router-dom';
import { Location } from 'history';
import { connect } from 'react-redux';

import { RootState } from '../app/reducer';

const mapStateToProps = (state: RootState) => {
  return {
    isLoggedIn: state.auth.jwt !== undefined,
  };
};

interface PublicRouteProps extends ReturnType<typeof mapStateToProps> {
  location?: Location;
  children?: React.ReactNode;
  path?: string | string[];
  exact?: boolean;
  sensitive?: boolean;
  strict?: boolean;
}

const PublicRoute = (props: PublicRouteProps) => {
  return (
    <Route
      path={props.path}
      exact={props.exact}
      location={props.location}
      sensitive={props.sensitive}
      strict={props.strict}
      render={(_props): JSX.Element => {
        if (props.isLoggedIn) {
          return (
            <Redirect to={{
              pathname: '/',
              push: false,
            }}
            />
          );
        }
        return <>{props.children}</>;
      }}
    />
  );
};

export default connect(mapStateToProps)(PublicRoute);
