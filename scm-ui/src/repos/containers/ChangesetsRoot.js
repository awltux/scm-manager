// @flow

import React from "react";
import { translate } from "react-i18next";
import { Route, withRouter } from "react-router-dom";
import { connect } from "react-redux";
import { compose } from "redux";
import type { Branch, Repository } from "@scm-manager/ui-types";
import {
  ErrorNotification,
  Loading,
  BranchSelector
} from "@scm-manager/ui-components";
import {
  fetchBranches,
  getBranches,
  getFetchBranchesFailure,
  isFetchBranchesPending
} from "../branches/modules/branches";
import Changesets from "./Changesets";

type Props = {
  repository: Repository,
  baseUrl: string,
  selected: string,
  baseUrlWithBranch: string,
  baseUrlWithoutBranch: string,

  // State props
  branches: Branch[],
  loading: boolean,
  error: Error,

  // Dispatch props
  fetchBranches: Repository => void,

  // Context props
  history: any, // TODO flow type
  match: any,
  t: string => string
};

class ChangesetsRoot extends React.Component<Props> {
  componentDidMount() {
    this.props.fetchBranches(this.props.repository);
  }

  stripEndingSlash = (url: string) => {
    if (url.endsWith("/")) {
      return url.substring(0, url.length - 1);
    }
    return url;
  };

  branchSelected = (branch?: Branch) => {
    let url;
    if (branch) {
      url = `${this.props.baseUrlWithBranch}/${encodeURIComponent(
        branch.name
      )}/changesets/`;
    } else {
      url = `${this.props.baseUrlWithoutBranch}/`;
    }
    this.props.history.push(url);
  };

  findSelectedBranch = () => {
    const { selected, branches } = this.props;
    return branches.find((branch: Branch) => branch.name === selected);
  };

  render() {
    const { repository, error, loading, match, branches } = this.props;

    if (error) {
      return <ErrorNotification error={error} />;
    }

    if (loading) {
      return <Loading />;
    }

    if (!repository || !branches) {
      return null;
    }

    const url = this.stripEndingSlash(match.url);
    const branch = this.findSelectedBranch();
    const changesets = <Changesets repository={repository} branch={branch} />;

    return (
      <div className="panel">
        <div className="panel-heading">{this.renderBranchSelector()}</div>
        <Route path={`${url}/:page?`} component={() => changesets} />
      </div>
    );
  }

  renderBranchSelector = () => {
    const { repository, branches, selected, t } = this.props;
    if (repository._links.branches) {
      return (
        <BranchSelector
          label={t("changesets.branchSelectorLabel")}
          branches={branches}
          selectedBranch={selected}
          selected={(b: Branch) => {
            this.branchSelected(b);
          }}
        />
      );
    }
    return null;
  };
}

const mapDispatchToProps = dispatch => {
  return {
    fetchBranches: (repo: Repository) => {
      dispatch(fetchBranches(repo));
    }
  };
};

const mapStateToProps = (state: any, ownProps: Props) => {
  const { repository, match } = ownProps;
  const loading = isFetchBranchesPending(state, repository);
  const error = getFetchBranchesFailure(state, repository);
  const branches = getBranches(state, repository);
  const selected = decodeURIComponent(match.params.branch);

  return {
    loading,
    error,
    branches,
    selected
  };
};

export default compose(
  withRouter,
  translate("repos"),
  connect(
    mapStateToProps,
    mapDispatchToProps
  )
)(ChangesetsRoot);
