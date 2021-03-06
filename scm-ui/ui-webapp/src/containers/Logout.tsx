import React from "react";
import { connect } from "react-redux";
import { WithTranslation, withTranslation } from "react-i18next";
import { Redirect } from "react-router-dom";

import { getLogoutFailure, isAuthenticated, isLogoutPending, isRedirecting, logout } from "../modules/auth";
import { ErrorPage, Loading } from "@scm-manager/ui-components";
import { getLogoutLink } from "../modules/indexResource";

type Props = WithTranslation & {
  authenticated: boolean;
  loading: boolean;
  redirecting: boolean;
  error: Error;
  logoutLink: string;

  // dispatcher functions
  logout: (link: string) => void;
};

class Logout extends React.Component<Props> {
  componentDidMount() {
    this.props.logout(this.props.logoutLink);
  }

  render() {
    const { authenticated, redirecting, loading, error, t } = this.props;
    if (error) {
      return <ErrorPage title={t("logout.error.title")} subtitle={t("logout.error.subtitle")} error={error} />;
    } else if (loading || authenticated || redirecting) {
      return <Loading />;
    } else {
      return <Redirect to="/login" />;
    }
  }
}

const mapStateToProps = (state: any) => {
  const authenticated = isAuthenticated(state);
  const loading = isLogoutPending(state);
  const redirecting = isRedirecting(state);
  const error = getLogoutFailure(state);
  const logoutLink = getLogoutLink(state);
  return {
    authenticated,
    loading,
    redirecting,
    error,
    logoutLink
  };
};

const mapDispatchToProps = (dispatch: any) => {
  return {
    logout: (link: string) => dispatch(logout(link))
  };
};

export default connect(mapStateToProps, mapDispatchToProps)(withTranslation("commons")(Logout));
