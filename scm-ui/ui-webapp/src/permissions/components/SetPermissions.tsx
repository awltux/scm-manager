import React from "react";
import { connect } from "react-redux";
import { WithTranslation, withTranslation } from "react-i18next";
import { Link } from "@scm-manager/ui-types";
import { ErrorNotification, Level, Notification, SubmitButton } from "@scm-manager/ui-components";
import { getLink } from "../../modules/indexResource";
import { loadPermissionsForEntity, setPermissions } from "./handlePermissions";
import PermissionsWrapper from "./PermissionsWrapper";

type Props = WithTranslation & {
  availablePermissionLink: string;
  selectedPermissionsLink: Link;
};

type State = {
  permissions: {
    [key: string]: boolean;
  };
  loading: boolean;
  error?: Error;
  permissionsChanged: boolean;
  permissionsSubmitted: boolean;
  overwritePermissionsLink?: Link;
};

class SetPermissions extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);

    this.state = {
      permissions: {},
      loading: true,
      permissionsChanged: false,
      permissionsSubmitted: false,
      overwritePermissionsLink: undefined
    };
  }

  setLoadingState = () => {
    this.setState({
      loading: true
    });
  };

  setErrorState = (error: Error) => {
    this.setState({
      error: error,
      loading: false
    });
  };

  setSuccessfulState = () => {
    this.setState({
      loading: false,
      error: undefined,
      permissionsSubmitted: true,
      permissionsChanged: false
    });
  };

  componentDidMount(): void {
    loadPermissionsForEntity(this.props.availablePermissionLink, this.props.selectedPermissionsLink.href).then(
      response => {
        const { permissions, overwriteLink } = response;
        this.setState({
          permissions: permissions,
          loading: false,
          overwritePermissionsLink: overwriteLink
        });
      }
    );
  }

  submit = (event: Event) => {
    event.preventDefault();
    if (this.state.permissions) {
      const { permissions } = this.state;
      this.setLoadingState();
      const selectedPermissions = Object.entries(permissions)
        .filter(e => e[1])
        .map(e => e[0]);
      if (this.state.overwritePermissionsLink) {
        setPermissions(this.state.overwritePermissionsLink.href, selectedPermissions)
          .then(result => {
            this.setSuccessfulState();
          })
          .catch(err => {
            this.setErrorState(err);
          });
      }
    }
  };

  render() {
    const { t } = this.props;
    const { loading, permissionsSubmitted, error } = this.state;

    let message = null;

    if (permissionsSubmitted) {
      message = (
        <Notification
          type={"success"}
          children={t("setPermissions.setPermissionsSuccessful")}
          onClose={() => this.onClose()}
        />
      );
    } else if (error) {
      message = <ErrorNotification error={error} />;
    }

    return (
      <form onSubmit={this.submit}>
        {message}
        {this.renderPermissions()}
        <Level
          right={
            <SubmitButton
              disabled={!this.state.permissionsChanged}
              loading={loading}
              label={t("setPermissions.button")}
            />
          }
        />
      </form>
    );
  }

  renderPermissions = () => {
    const { overwritePermissionsLink, permissions } = this.state;
    return (
      <PermissionsWrapper permissions={permissions} onChange={this.valueChanged} disabled={!overwritePermissionsLink} />
    );
  };

  valueChanged = (value: boolean, name: string) => {
    this.setState(state => {
      const newPermissions = state.permissions;
      newPermissions[name] = value;
      return {
        permissions: newPermissions,
        permissionsChanged: true
      };
    });
  };

  onClose = () => {
    this.setState({
      permissionsSubmitted: false
    });
  };
}

const mapStateToProps = (state: any) => {
  const availablePermissionLink = getLink(state, "permissions");
  return {
    availablePermissionLink
  };
};

export default connect(mapStateToProps)(withTranslation("permissions")(SetPermissions));
