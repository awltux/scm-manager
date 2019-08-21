//@flow
import React from "react";
import {Change, Diff as DiffComponent, DiffObjectProps, File, getChangeKey, Hunk} from "react-diff-view";
import injectSheets from "react-jss";
import classNames from "classnames";
import {translate} from "react-i18next";
import {Button, ButtonGroup} from "../buttons";

const styles = {
  panel: {
    fontSize: "1rem"
  },
  /* breaks into a second row
     when buttons and title become too long */
  level: {
    flexWrap: "wrap"
  },
  titleHeader: {
    display: "flex",
    maxWidth: "100%",
    cursor: "pointer"
  },
  title: {
    marginLeft: ".25rem",
    fontSize: "1rem"
  },
  /* align child to right */
  buttonHeader: {
    display: "flex",
    marginLeft: "auto"
  },
  hunkDivider: {
    margin: ".5rem 0"
  },
  changeType: {
    marginLeft: ".75rem"
  }
};

type Props = DiffObjectProps & {
  file: File,
  collapsible: true,
  // context props
  classes: any,
  t: string => string
};

type State = {
  collapsed: boolean,
  sideBySide: boolean
};

class DiffFile extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      collapsed: false,
      sideBySide: false
    };
  }

  toggleCollapse = () => {
    if (this.props.collapsable) {
      this.setState(state => ({
        collapsed: !state.collapsed
      }));
    }
  };

  toggleSideBySide = () => {
    this.setState(state => ({
      sideBySide: !state.sideBySide
    }));
  };

  setCollapse = (collapsed: boolean) => {
    this.setState({
      collapsed
    });
  };

  createHunkHeader = (hunk: Hunk, i: number) => {
    const { classes } = this.props;
    if (i > 0) {
      return <hr className={classes.hunkDivider} />;
    }
    return null;
  };

  collectHunkAnnotations = (hunk: Hunk) => {
    const { annotationFactory, file } = this.props;
    if (annotationFactory) {
      return annotationFactory({
        hunk,
        file
      });
    }
  };

  handleClickEvent = (change: Change, hunk: Hunk) => {
    const { file, onClick } = this.props;
    const context = {
      changeId: getChangeKey(change),
      change,
      hunk,
      file
    };
    if (onClick) {
      onClick(context);
    }
  };

  createCustomEvents = (hunk: Hunk) => {
    const { onClick } = this.props;
    if (onClick) {
      return {
        gutter: {
          onClick: (change: Change) => {
            this.handleClickEvent(change, hunk);
          }
        }
      };
    }
  };

  renderHunk = (hunk: Hunk, i: number) => {
    return (
      <Hunk
        key={hunk.content}
        hunk={hunk}
        header={this.createHunkHeader(hunk, i)}
        widgets={this.collectHunkAnnotations(hunk)}
        customEvents={this.createCustomEvents(hunk)}
      />
    );
  };

  renderFileTitle = (file: any) => {
    if (
      file.oldPath !== file.newPath &&
      (file.type === "copy" || file.type === "rename")
    ) {
      return (
        <>
          {file.oldPath} <i className="fa fa-arrow-right" /> {file.newPath}
        </>
      );
    } else if (file.type === "delete") {
      return file.oldPath;
    }
    return file.newPath;
  };

  hoverFileTitle = (file: any) => {
    if (
      file.oldPath !== file.newPath &&
      (file.type === "copy" || file.type === "rename")
    ) {
      return (
        <>
          {file.oldPath} > {file.newPath}
        </>
      );
    } else if (file.type === "delete") {
      return file.oldPath;
    }
    return file.newPath;
  };

  renderChangeTag = (file: any) => {
    const { t, classes } = this.props;
    if (!file.type) {
      return;
    }
    const key = "diff.changes." + file.type;
    let value = t(key);
    if (key === value) {
      value = file.type;
    }
    const color =
      value === "added"
        ? "is-success"
        : value === "deleted"
          ? "is-danger"
          : "is-info";

    return (
      <span
        className={classNames(
          "tag",
          "is-rounded",
          "has-text-weight-normal",
          color,
          classes.changeType
        )}
      >
        {value}
      </span>
    );
  };

  render() {
    const {
      file,
      fileControlFactory,
      fileAnnotationFactory,
      collapsible,
      classes,
      t
    } = this.props;
    const { collapsed, sideBySide } = this.state;
    const viewType = sideBySide ? "split" : "unified";

    let body = null;
    let icon = "fa fa-angle-right";
    if (!collapsed) {
      const fileAnnotations = fileAnnotationFactory
        ? fileAnnotationFactory(file)
        : null;
      icon = "fa fa-angle-down";
      body = (
        <div className="panel-block is-paddingless is-size-7">
          {fileAnnotations}
          <DiffComponent viewType={viewType}>
            {file.hunks.map(this.renderHunk)}
          </DiffComponent>
        </div>
      );
    }
    const collapseIcon = collapsible? <i className={icon} />: null;

    const fileControls = fileControlFactory
      ? fileControlFactory(file, this.setCollapse)
      : null;
    return (
      <div className={classNames("panel", classes.panel)}>
        <div className="panel-heading">
          <div className={classNames("level", classes.level)}>
            <div
              className={classNames("level-left", classes.titleHeader)}
              onClick={this.toggleCollapse}
              title={this.hoverFileTitle(file)}
            >
              {collapseIcon}
              <span
                className={classNames("is-ellipsis-overflow", classes.title)}
              >
                {this.renderFileTitle(file)}
              </span>
              {this.renderChangeTag(file)}
            </div>
            <div className={classNames("level-right", classes.buttonHeader)}>
              <ButtonGroup>
                <Button
                  action={this.toggleSideBySide}
                  className="reduced-mobile"
                >
                  <span className="icon is-small">
                    <i
                      className={classNames(
                        "fas",
                        sideBySide ? "fa-align-left" : "fa-columns"
                      )}
                    />
                  </span>
                  <span>
                    {t(sideBySide ? "diff.combined" : "diff.sideBySide")}
                  </span>
                </Button>
                {fileControls}
              </ButtonGroup>
            </div>
          </div>
        </div>
        {body}
      </div>
    );
  }
}

export default injectSheets(styles)(translate("repos")(DiffFile));
