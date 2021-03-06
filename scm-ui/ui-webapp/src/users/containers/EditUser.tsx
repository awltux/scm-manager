import React from "react";
import { connect } from "react-redux";
import { withRouter } from "react-router-dom";
import UserForm from "../components/UserForm";
import DeleteUser from "./DeleteUser";
import { User } from "@scm-manager/ui-types";
import { getModifyUserFailure, isModifyUserPending, modifyUser, modifyUserReset } from "../modules/users";
import { History } from "history";
import { ErrorNotification } from "@scm-manager/ui-components";
import { compose } from "redux";

type Props = {
  loading: boolean;
  error: Error;

  // dispatch functions
  modifyUser: (user: User, callback?: () => void) => void;
  modifyUserReset: (p: User) => void;

  // context objects
  user: User;
  history: History;
};

class EditUser extends React.Component<Props> {
  componentDidMount() {
    const { modifyUserReset, user } = this.props;
    modifyUserReset(user);
  }

  userModified = (user: User) => () => {
    this.props.history.push(`/user/${user.name}`);
  };

  modifyUser = (user: User) => {
    this.props.modifyUser(user, this.userModified(user));
  };

  render() {
    const { user, loading, error } = this.props;
    return (
      <div>
        <ErrorNotification error={error} />
        <UserForm submitForm={user => this.modifyUser(user)} user={user} loading={loading} />
        <DeleteUser user={user} />
      </div>
    );
  }
}

const mapStateToProps = (state: any, ownProps: Props) => {
  const loading = isModifyUserPending(state, ownProps.user.name);
  const error = getModifyUserFailure(state, ownProps.user.name);
  return {
    loading,
    error
  };
};

const mapDispatchToProps = (dispatch: any) => {
  return {
    modifyUser: (user: User, callback?: () => void) => {
      dispatch(modifyUser(user, callback));
    },
    modifyUserReset: (user: User) => {
      dispatch(modifyUserReset(user));
    }
  };
};

export default compose(connect(mapStateToProps, mapDispatchToProps), withRouter)(EditUser);
