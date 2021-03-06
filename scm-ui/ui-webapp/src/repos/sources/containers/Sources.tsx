import React from "react";
import { connect } from "react-redux";
import { withRouter, RouteComponentProps } from "react-router-dom";
import { WithTranslation, withTranslation } from "react-i18next";
import { Branch, Repository } from "@scm-manager/ui-types";
import { Breadcrumb, ErrorNotification, Loading } from "@scm-manager/ui-components";
import FileTree from "../components/FileTree";
import { getFetchBranchesFailure, isFetchBranchesPending } from "../../branches/modules/branches";
import { compose } from "redux";
import Content from "./Content";
import { fetchSources, getSources, isDirectory } from "../modules/sources";
import CodeActionBar from "../../codeSection/components/CodeActionBar";

type Props = WithTranslation &
  RouteComponentProps & {
    repository: Repository;
    loading: boolean;
    error: Error;
    baseUrl: string;
    branches: Branch[];
    revision: string;
    path: string;
    currentFileIsDirectory: boolean;
    sources: File;
    selectedBranch: string;

    // dispatch props
    fetchSources: (repository: Repository, revision: string, path: string) => void;
  };

class Sources extends React.Component<Props> {
  componentDidMount() {
    const { repository, branches, selectedBranch, baseUrl, revision, path, fetchSources } = this.props;
    fetchSources(repository, this.decodeRevision(revision), path);
    if (branches?.length > 0 && !selectedBranch) {
      const defaultBranch = branches?.filter(b => b.defaultBranch === true)[0];
      this.props.history.replace(`${baseUrl}/sources/${encodeURIComponent(defaultBranch.name)}/`);
    }
  }

  componentDidUpdate(prevProps: Props) {
    const { fetchSources, repository, revision, path } = this.props;
    if (prevProps.revision !== revision || prevProps.path !== path) {
      fetchSources(repository, this.decodeRevision(revision), path);
    }
  }

  decodeRevision = (revision: string) => {
    return revision ? decodeURIComponent(revision) : revision;
  };

  onSelectBranch = (branch?: Branch) => {
    const { baseUrl, history, path } = this.props;
    let url;
    if (branch) {
      if (path) {
        url = `${baseUrl}/sources/${encodeURIComponent(branch.name)}/${path}`;
        url = !url.endsWith("/") ? url + "/" : url;
      } else {
        url = `${baseUrl}/sources/${encodeURIComponent(branch.name)}/`;
      }
    } else {
      return;
    }
    history.push(url);
  };

  evaluateSwitchViewLink = () => {
    const { baseUrl, selectedBranch, branches } = this.props;
    if (branches && selectedBranch && branches?.filter(b => b.name === selectedBranch).length !== 0) {
      return `${baseUrl}/branch/${encodeURIComponent(selectedBranch)}/changesets/`;
    }
    return `${baseUrl}/changesets/`;
  };

  render() {
    const {
      repository,
      baseUrl,
      branches,
      selectedBranch,
      loading,
      error,
      revision,
      path,
      currentFileIsDirectory
    } = this.props;

    if (error) {
      return <ErrorNotification error={error} />;
    }

    if (loading) {
      return <Loading />;
    }

    if (currentFileIsDirectory) {
      return (
        <>
          <CodeActionBar
            selectedBranch={selectedBranch}
            branches={branches}
            onSelectBranch={this.onSelectBranch}
            switchViewLink={this.evaluateSwitchViewLink()}
          />
          <div className="panel">
            {this.renderBreadcrumb()}
            <FileTree repository={repository} revision={revision} path={path} baseUrl={baseUrl + "/sources"} />
          </div>
        </>
      );
    } else {
      return (
        <>
          <CodeActionBar
            selectedBranch={selectedBranch}
            branches={branches}
            onSelectBranch={this.onSelectBranch}
            switchViewLink={this.evaluateSwitchViewLink()}
          />
          <Content repository={repository} revision={revision} path={path} breadcrumb={this.renderBreadcrumb()} />
        </>
      );
    }
  }

  renderBreadcrumb = () => {
    const { revision, selectedBranch, path, baseUrl, branches, sources, repository } = this.props;

    return (
      <Breadcrumb
        repository={repository}
        revision={revision}
        path={path}
        baseUrl={baseUrl + "/sources"}
        branch={branches?.filter(b => b.name === selectedBranch)[0]}
        defaultBranch={branches?.filter(b => b.defaultBranch === true)[0]}
        sources={sources}
      />
    );
  };
}

const mapStateToProps = (state: any, ownProps: Props) => {
  const { repository, match } = ownProps;
  const { revision, path } = match.params;
  const decodedRevision = revision ? decodeURIComponent(revision) : undefined;
  const loading = isFetchBranchesPending(state, repository);
  const error = getFetchBranchesFailure(state, repository);
  const currentFileIsDirectory = decodedRevision
    ? isDirectory(state, repository, decodedRevision, path)
    : isDirectory(state, repository, revision, path);
  const sources = getSources(state, repository, decodedRevision, path);

  return {
    repository,
    revision,
    path,
    loading,
    error,
    currentFileIsDirectory,
    sources
  };
};

const mapDispatchToProps = (dispatch: any) => {
  return {
    fetchSources: (repository: Repository, revision: string, path: string) => {
      dispatch(fetchSources(repository, revision, path));
    }
  };
};

export default compose(withTranslation("repos"), withRouter, connect(mapStateToProps, mapDispatchToProps))(Sources);
