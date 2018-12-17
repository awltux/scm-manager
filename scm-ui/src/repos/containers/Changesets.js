// @flow

import React from "react";
import {withRouter} from "react-router-dom";
import type {Branch, Changeset, PagedCollection, Repository} from "@scm-manager/ui-types";
import {
  fetchChangesets,
  getChangesets,
  getFetchChangesetsFailure,
  isFetchChangesetsPending,
  selectListAsCollection
} from "../modules/changesets";

import {connect} from "react-redux";
import {ErrorNotification, getPageFromMatch, LinkPaginator, ChangesetList, Loading} from "@scm-manager/ui-components";
import {compose} from "redux";

type Props = {
  repository: Repository,
  branch: Branch,
  page: number,

  // State props
  changesets: Changeset[],
  list: PagedCollection,
  loading: boolean,
  error: Error,

  // Dispatch props
  fetchChangesets: (Repository, Branch, number) => void,

  // context props
  match: any
};

class Changesets extends React.Component<Props> {
  componentDidMount() {
    const { fetchChangesets, repository, branch, page } = this.props;

    fetchChangesets(repository, branch, page);
  }

  render() {
    const { changesets, loading, error } = this.props;

    if (error) {
      return <ErrorNotification error={error} />;
    }

    if (loading) {
      return <Loading />;
    }

    if (!changesets || changesets.length === 0) {
      return null;
    }
    return (
      <>
        {this.renderList()}
        {this.renderPaginator()}
      </>
    );
  }

  renderList = () => {
    const { repository, changesets } = this.props;
    return <ChangesetList repository={repository} changesets={changesets} />;
  };

  renderPaginator = () => {
    const { page, list } = this.props;
    if (list) {
      return <LinkPaginator page={page} collection={list} />;
    }
    return null;
  };
}

const mapDispatchToProps = dispatch => {
  return {
    fetchChangesets: (repo: Repository, branch: Branch, page: number) => {
      dispatch(fetchChangesets(repo, branch, page));
    }
  };
};

const mapStateToProps = (state: any, ownProps: Props) => {
  const { repository, branch, match } = ownProps;
  const changesets = getChangesets(state, repository, branch);
  const loading = isFetchChangesetsPending(state, repository, branch);
  const error = getFetchChangesetsFailure(state, repository, branch);
  const list = selectListAsCollection(state, repository, branch);
  const page = getPageFromMatch(match);

  return { changesets, list, page, loading, error };
};

export default compose(
  withRouter,
  connect(
    mapStateToProps,
    mapDispatchToProps
  )
)(Changesets);
