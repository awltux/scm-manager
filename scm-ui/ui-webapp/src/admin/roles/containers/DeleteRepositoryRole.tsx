import React from "react";
import { connect } from "react-redux";
import { compose } from "redux";
import { withRouter } from "react-router-dom";
import { WithTranslation, withTranslation } from "react-i18next";
import { History } from "history";
import { RepositoryRole } from "@scm-manager/ui-types";
import { confirmAlert, DeleteButton, ErrorNotification, Level } from "@scm-manager/ui-components";
import { deleteRole, getDeleteRoleFailure, isDeleteRolePending } from "../modules/roles";

type Props = WithTranslation & {
  loading: boolean;
  error: Error;
  role: RepositoryRole;
  confirmDialog?: boolean;
  deleteRole: (role: RepositoryRole, callback?: () => void) => void;

  // context props
  history: History;
};

class DeleteRepositoryRole extends React.Component<Props> {
  static defaultProps = {
    confirmDialog: true
  };

  roleDeleted = () => {
    this.props.history.push("/admin/roles/");
  };

  deleteRole = () => {
    this.props.deleteRole(this.props.role, this.roleDeleted);
  };

  confirmDelete = () => {
    const { t } = this.props;
    confirmAlert({
      title: t("repositoryRole.delete.confirmAlert.title"),
      message: t("repositoryRole.delete.confirmAlert.message"),
      buttons: [
        {
          className: "is-outlined",
          label: t("repositoryRole.delete.confirmAlert.submit"),
          onClick: () => this.deleteRole()
        },
        {
          label: t("repositoryRole.delete.confirmAlert.cancel"),
          onClick: () => null
        }
      ]
    });
  };

  isDeletable = () => {
    return this.props.role._links.delete;
  };

  render() {
    const { loading, error, confirmDialog, t } = this.props;
    const action = confirmDialog ? this.confirmDelete : this.deleteRole;

    if (!this.isDeletable()) {
      return null;
    }

    return (
      <>
        <hr />
        <ErrorNotification error={error} />
        <Level right={<DeleteButton label={t("repositoryRole.delete.button")} action={action} loading={loading} />} />
      </>
    );
  }
}

const mapStateToProps = (state: any, ownProps: Props) => {
  const loading = isDeleteRolePending(state, ownProps.role.name);
  const error = getDeleteRoleFailure(state, ownProps.role.name);
  return {
    loading,
    error
  };
};

const mapDispatchToProps = (dispatch: any) => {
  return {
    deleteRole: (role: RepositoryRole, callback?: () => void) => {
      dispatch(deleteRole(role, callback));
    }
  };
};

export default compose(
  connect(mapStateToProps, mapDispatchToProps),
  withRouter,
  withTranslation("admin")
)(DeleteRepositoryRole);
