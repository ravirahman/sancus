import React from 'react';

import { Route, Redirect } from 'react-router-dom';
import { Location } from 'history';
import { connect } from 'react-redux';
import { RootState } from '../app/reducer';

export interface LocationState {
  from: Location
}

const mapStateToProps = (state: RootState) => {
  return {
    isLoggedIn: state.auth.jwt !== undefined,
  };
};

interface PrivateRouteProps extends ReturnType<typeof mapStateToProps> {
  location?: Location;
  children?: React.ReactNode;
  path?: string | string[];
  exact?: boolean;
  sensitive?: boolean;
  strict?: boolean;
}

const PrivateRoute = (props: PrivateRouteProps) => {
  const { isLoggedIn, children } = props;
  return (
    <Route
      path={props.path}
      exact={props.exact}
      location={props.location}
      sensitive={props.sensitive}
      strict={props.strict}
      render={() => {
        if (isLoggedIn) {
          return <>{children}</>;
        }
        return (
          <Redirect to={{
            pathname: '/auth',
            state: {
              from: props.location,
            } as LocationState,
          }}
          />
        );
      }}
    />
  );
};

export default connect(mapStateToProps)(PrivateRoute);
