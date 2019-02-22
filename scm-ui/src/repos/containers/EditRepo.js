// @flow
import React from "react";
import { connect } from "react-redux";
import { withRouter } from "react-router-dom";
import RepositoryForm from "../components/form";
import DeleteRepo from "./DeleteRepo";
import type { Repository } from "@scm-manager/ui-types";
import {
  modifyRepo,
  isModifyRepoPending,
  getModifyRepoFailure,
  isPermittedToModifyRepo,
  modifyRepoReset
} from "../modules/repos";
import type { History } from "history";
import { ErrorNotification } from "@scm-manager/ui-components";
import { ExtensionPoint } from "@scm-manager/ui-extensions";

type Props = {
  loading: boolean,
  error: Error,
  canModifyRepo: boolean,

  modifyRepo: (Repository, () => void) => void,
  modifyRepoReset: Repository => void,

  // context props
  repository: Repository,
  history: History,
  match: any
};

class EditRepo extends React.Component<Props> {
  componentDidMount() {
    const { modifyRepoReset, repository } = this.props;
    modifyRepoReset(repository);
  }

  repoModified = () => {
    const { history, repository } = this.props;
    history.push(`/repo/${repository.namespace}/${repository.name}`);
  };

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
    const { error, repository } = this.props;

    const url = this.matchedUrl();

    const extensionProps = {
      repository,
      url
    };

    return (
      <div>
        <ErrorNotification error={error} />
        {this.renderRepositoryForm()}
        <ExtensionPoint
          name="repo-config.route"
          props={extensionProps}
          renderAll={true}
        />
        <DeleteRepo repository={repository} />
      </div>
    );
  }

  renderRepositoryForm() {
    const { canModifyRepo, repository, loading } = this.props;
    if(canModifyRepo) {
      return (
        <RepositoryForm
          repository={repository}
          loading={loading}
          submitForm={repo => {
            this.props.modifyRepo(repo, this.repoModified);
          }}
        />
      );
    }
  }
}

const mapStateToProps = (state, ownProps) => {
  const { namespace, name } = ownProps.repository;
  const loading = isModifyRepoPending(state, namespace, name);
  const error = getModifyRepoFailure(state, namespace, name);
  const canModifyRepo = isPermittedToModifyRepo(ownProps.repository);
  return {
    loading,
    error,
    canModifyRepo
  };
};

const mapDispatchToProps = dispatch => {
  return {
    modifyRepo: (repo: Repository, callback: () => void) => {
      dispatch(modifyRepo(repo, callback));
    },
    modifyRepoReset: (repo: Repository) => {
      dispatch(modifyRepoReset(repo));
    }
  };
};

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(withRouter(EditRepo));
