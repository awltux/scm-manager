import React from "react";
import { connect } from "react-redux";
import { compose } from "redux";
import { withRouter } from "react-router-dom";
import { WithTranslation, withTranslation } from "react-i18next";
import { History } from "history";
import { Group } from "@scm-manager/ui-types";
import { confirmAlert, DeleteButton, ErrorNotification, Level } from "@scm-manager/ui-components";
import { deleteGroup, getDeleteGroupFailure, isDeleteGroupPending } from "../modules/groups";

type Props = WithTranslation & {
  loading: boolean;
  error: Error;
  group: Group;
  confirmDialog?: boolean;
  deleteGroup: (group: Group, callback?: () => void) => void;

  // context props
  history: History;
};

export class DeleteGroup extends React.Component<Props> {
  static defaultProps = {
    confirmDialog: true
  };

  deleteGroup = () => {
    this.props.deleteGroup(this.props.group, this.groupDeleted);
  };

  groupDeleted = () => {
    this.props.history.push("/groups/");
  };

  confirmDelete = () => {
    const { t } = this.props;
    confirmAlert({
      title: t("deleteGroup.confirmAlert.title"),
      message: t("deleteGroup.confirmAlert.message"),
      buttons: [
        {
          className: "is-outlined",
          label: t("deleteGroup.confirmAlert.submit"),
          onClick: () => this.deleteGroup()
        },
        {
          label: t("deleteGroup.confirmAlert.cancel"),
          onClick: () => null
        }
      ]
    });
  };

  isDeletable = () => {
    return this.props.group._links.delete;
  };

  render() {
    const { loading, error, confirmDialog, t } = this.props;
    const action = confirmDialog ? this.confirmDelete : this.deleteGroup;

    if (!this.isDeletable()) {
      return null;
    }

    return (
      <>
        <hr />
        <ErrorNotification error={error} />
        <Level right={<DeleteButton label={t("deleteGroup.button")} action={action} loading={loading} />} />
      </>
    );
  }
}

const mapStateToProps = (state: any, ownProps: Props) => {
  const loading = isDeleteGroupPending(state, ownProps.group.name);
  const error = getDeleteGroupFailure(state, ownProps.group.name);
  return {
    loading,
    error
  };
};

const mapDispatchToProps = (dispatch: any) => {
  return {
    deleteGroup: (group: Group, callback?: () => void) => {
      dispatch(deleteGroup(group, callback));
    }
  };
};

export default compose(
  connect(mapStateToProps, mapDispatchToProps),
  withRouter,
  withTranslation("groups")
)(DeleteGroup);
