//@flow
import React from "react";

import { Route, Redirect, withRouter } from "react-router";

import Overview from "../repos/containers/Overview";
import Users from "../users/containers/Users";
import Login from "../containers/Login";
import Logout from "../containers/Logout";

import { Switch } from "react-router-dom";
import ProtectedRoute from "../components/ProtectedRoute";
import AddUser from "../users/containers/AddUser";
import SingleUser from "../users/containers/SingleUser";
import RepositoryRoot from "../repos/containers/RepositoryRoot";
import Create from "../repos/containers/Create";

import Groups from "../groups/containers/Groups";
import SingleGroup from "../groups/containers/SingleGroup";
import AddGroup from "../groups/containers/AddGroup";

import Config from "../config/containers/Config";

type Props = {
  authenticated?: boolean
};

class Main extends React.Component<Props> {
  render() {
    const { authenticated } = this.props;
    return (
      <div className="main">
        <Switch>
          <Redirect exact path="/" to="/repos" />
          <Route exact path="/login" component={Login} />
          <Route path="/logout" component={Logout} />
          <ProtectedRoute
            exact
            path="/repos"
            component={Overview}
            authenticated={authenticated}
          />
          <ProtectedRoute
            exact
            path="/repos/create"
            component={Create}
            authenticated={authenticated}
          />
          <ProtectedRoute
            exact
            path="/repos/:page"
            component={Overview}
            authenticated={authenticated}
          />
          <ProtectedRoute
            path="/repo/:namespace/:name"
            component={RepositoryRoot}
            authenticated={authenticated}
          />
          <ProtectedRoute
            exact
            path="/users"
            component={Users}
            authenticated={authenticated}
          />
          <ProtectedRoute
            authenticated={authenticated}
            path="/users/add"
            component={AddUser}
          />
          <ProtectedRoute
            exact
            path="/users/:page"
            component={Users}
            authenticated={authenticated}
          />
          <ProtectedRoute
            authenticated={authenticated}
            path="/user/:name"
            component={SingleUser}
          />
          <ProtectedRoute
            exact
            path="/groups"
            component={Groups}
            authenticated={authenticated}
          />
          <ProtectedRoute
            authenticated={authenticated}
            path="/group/:name"
            component={SingleGroup}
          />
          <ProtectedRoute
            authenticated={authenticated}
            path="/groups/add"
            component={AddGroup}
          />
          <ProtectedRoute
            exact
            path="/groups/:page"
            component={Groups}
            authenticated={authenticated}
    />
    < ProtectedRoute
    exact
    path = "/config"
    component = {Config}
    authenticated = {authenticated}
          />
        </Switch>
      </div>
    );
  }
}

export default withRouter(Main);
