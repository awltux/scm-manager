import React from "react";
import { Route, withRouter } from "react-router-dom";
import { getMe } from "../modules/auth";
import { compose } from "redux";
import { connect } from "react-redux";
import { WithTranslation, withTranslation } from "react-i18next";
import { Me } from "@scm-manager/ui-types";
import { ErrorPage, Navigation, NavLink, Page, Section, SubNavigation } from "@scm-manager/ui-components";
import ChangeUserPassword from "./ChangeUserPassword";
import ProfileInfo from "./ProfileInfo";
import { ExtensionPoint } from "@scm-manager/ui-extensions";

type Props = WithTranslation & {
  me: Me;

  // Context props
  match: any;
};
type State = {};

class Profile extends React.Component<Props, State> {
  stripEndingSlash = (url: string) => {
    if (url.endsWith("/")) {
      return url.substring(0, url.length - 2);
    }
    return url;
  };

  matchedUrl = () => {
    return this.stripEndingSlash(this.props.match.url);
  };

  render() {
    const url = this.matchedUrl();

    const { me, t } = this.props;

    if (!me) {
      return (
        <ErrorPage
          title={t("profile.error-title")}
          subtitle={t("profile.error-subtitle")}
          error={{
            name: t("profile.error"),
            message: t("profile.error-message")
          }}
        />
      );
    }

    const extensionProps = {
      me,
      url
    };

    return (
      <Page title={me.displayName}>
        <div className="columns">
          <div className="column is-three-quarters">
            <Route path={url} exact render={() => <ProfileInfo me={me} />} />
            <Route path={`${url}/settings/password`} render={() => <ChangeUserPassword me={me} />} />
            <ExtensionPoint name="profile.route" props={extensionProps} renderAll={true} />
          </div>
          <div className="column">
            <Navigation>
              <Section label={t("profile.navigationLabel")}>
                <NavLink to={`${url}`} icon="fas fa-info-circle" label={t("profile.informationNavLink")} />
                <SubNavigation to={`${url}/settings/password`} label={t("profile.settingsNavLink")}>
                  <NavLink to={`${url}/settings/password`} label={t("profile.changePasswordNavLink")} />
                  <ExtensionPoint name="profile.setting" props={extensionProps} renderAll={true} />
                </SubNavigation>
              </Section>
            </Navigation>
          </div>
        </div>
      </Page>
    );
  }
}

const mapStateToProps = (state: any) => {
  return {
    me: getMe(state)
  };
};

export default compose(withTranslation("commons"), connect(mapStateToProps), withRouter)(Profile);
