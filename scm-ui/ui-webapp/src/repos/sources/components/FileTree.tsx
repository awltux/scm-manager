import React from "react";
import { compose } from "redux";
import { connect } from "react-redux";
import { withRouter } from "react-router-dom";
import { WithTranslation, withTranslation } from "react-i18next";
import styled from "styled-components";
import { binder } from "@scm-manager/ui-extensions";
import { File, Repository } from "@scm-manager/ui-types";
import { ErrorNotification, Loading, Notification } from "@scm-manager/ui-components";
import { fetchSources, getFetchSourcesFailure, getSources, isFetchSourcesPending } from "../modules/sources";
import FileTreeLeaf from "./FileTreeLeaf";

type Props = WithTranslation & {
  loading: boolean;
  error: Error;
  tree: File;
  repository: Repository;
  revision: string;
  path: string;
  baseUrl: string;

  updateSources: () => void;

  // context props
  match: any;
};

type State = {
  stoppableUpdateHandler?: number;
};

const FixedWidthTh = styled.th`
  width: 16px;
`;

export function findParent(path: string) {
  if (path.endsWith("/")) {
    path = path.substring(0, path.length - 1);
  }

  const index = path.lastIndexOf("/");
  if (index > 0) {
    return path.substring(0, index);
  }
  return "";
}

class FileTree extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {};
  }

  componentDidUpdate(prevProps: Readonly<Props>, prevState: Readonly<State>): void {
    if (prevState.stoppableUpdateHandler === this.state.stoppableUpdateHandler) {
      const { tree, updateSources } = this.props;
      if (tree?._embedded?.children && tree._embedded.children.find(c => c.partialResult)) {
        const stoppableUpdateHandler = setTimeout(updateSources, 3000);
        this.setState({ stoppableUpdateHandler: stoppableUpdateHandler });
      }
    }
  }

  componentWillUnmount(): void {
    if (this.state.stoppableUpdateHandler) {
      clearTimeout(this.state.stoppableUpdateHandler);
    }
  }

  render() {
    const { error, loading, tree } = this.props;

    if (error) {
      return <ErrorNotification error={error} />;
    }

    if (loading) {
      return <Loading />;
    }
    if (!tree) {
      return null;
    }

    return <div className="panel-block">{this.renderSourcesTable()}</div>;
  }

  renderSourcesTable() {
    const { tree, revision, path, baseUrl, t } = this.props;

    const files = [];

    if (path) {
      files.push({
        name: "..",
        path: findParent(path),
        directory: true
      });
    }

    const compareFiles = function(f1: File, f2: File): number {
      if (f1.directory) {
        if (f2.directory) {
          return f1.name.localeCompare(f2.name);
        } else {
          return -1;
        }
      } else {
        if (f2.directory) {
          return 1;
        } else {
          return f1.name.localeCompare(f2.name);
        }
      }
    };

    if (tree._embedded && tree._embedded.children) {
      const children = [...tree._embedded.children].sort(compareFiles);
      files.push(...children);
    }

    if (files && files.length > 0) {
      let baseUrlWithRevision = baseUrl;
      if (revision) {
        baseUrlWithRevision += "/" + encodeURIComponent(revision);
      } else {
        baseUrlWithRevision += "/" + encodeURIComponent(tree.revision);
      }

      return (
        <table className="table table-hover table-sm is-fullwidth">
          <thead>
            <tr>
              <FixedWidthTh />
              <th>{t("sources.file-tree.name")}</th>
              <th className="is-hidden-mobile">{t("sources.file-tree.length")}</th>
              <th className="is-hidden-mobile">{t("sources.file-tree.commitDate")}</th>
              <th className="is-hidden-touch">{t("sources.file-tree.description")}</th>
              {binder.hasExtension("repos.sources.tree.row.right") && <th className="is-hidden-mobile" />}
            </tr>
          </thead>
          <tbody>
            {files.map(file => (
              <FileTreeLeaf key={file.name} file={file} baseUrl={baseUrlWithRevision} />
            ))}
          </tbody>
        </table>
      );
    }
    return <Notification type="info">{t("sources.noSources")}</Notification>;
  }
}

const mapDispatchToProps = (dispatch: any, ownProps: Props) => {
  const { repository, revision, path } = ownProps;

  const updateSources = () => dispatch(fetchSources(repository, revision, path, false));

  return { updateSources };
};

const mapStateToProps = (state: any, ownProps: Props) => {
  const { repository, revision, path } = ownProps;

  const loading = isFetchSourcesPending(state, repository, revision, path);
  const error = getFetchSourcesFailure(state, repository, revision, path);
  const tree = getSources(state, repository, revision, path);

  return {
    revision,
    path,
    loading,
    error,
    tree
  };
};

export default compose(withRouter, connect(mapStateToProps, mapDispatchToProps))(withTranslation("repos")(FileTree));
