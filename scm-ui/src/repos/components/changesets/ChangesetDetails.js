//@flow
import React from "react";
import type { Changeset, Repository } from "@scm-manager/ui-types";
import { Interpolate, translate } from "react-i18next";
import injectSheet from "react-jss";

import {
  DateFromNow,
  ChangesetId,
  ChangesetTag,
  ChangesetAuthor,
  ChangesetDiff,
  AvatarWrapper,
  AvatarImage,
  changesets,
} from "@scm-manager/ui-components";

import classNames from "classnames";
import type { Tag } from "@scm-manager/ui-types";

const styles = {
  spacing: {
    marginRight: "1em"
  }
};

type Props = {
  changeset: Changeset,
  repository: Repository,
  t: string => string,
  classes: any
};

class ChangesetDetails extends React.Component<Props> {
  render() {
    const { changeset, repository, classes } = this.props;

    const description = changesets.parseDescription(changeset.description);

    const id = (
      <ChangesetId repository={repository} changeset={changeset} link={false}/>
    );
    const date = <DateFromNow date={changeset.date}/>;

    return (
      <div>
        <div className="content">
          <h4>{description.title}</h4>
          <article className="media">
            <AvatarWrapper>
              <p className={classNames("image", "is-64x64", classes.spacing)}>
                <AvatarImage person={changeset.author} />
              </p>
            </AvatarWrapper>
            <div className="media-content">
              <p>
                <ChangesetAuthor changeset={changeset}/>
              </p>
              <p>
                <Interpolate
                  i18nKey="changesets.changeset.summary"
                  id={id}
                  time={date}
                />
              </p>
            </div>
            <div className="media-right">{this.renderTags()}</div>
          </article>
          <p>
            {description.message.split("\n").map((item, key) => {
              return (
                <span key={key}>
                  {item}
                  <br/>
                </span>
              );
            })}
          </p>
        </div>
        <div>
          <ChangesetDiff changeset={changeset} />
        </div>
      </div>
    );
  }

  getTags = () => {
    const { changeset } = this.props;
    return changeset._embedded.tags || [];
  };

  renderTags = () => {
    const tags = this.getTags();
    if (tags.length > 0) {
      return (
        <div className="level-item">
          {tags.map((tag: Tag) => {
            return <ChangesetTag key={tag.name} tag={tag}/>;
          })}
        </div>
      );
    }
    return null;
  };
}

export default injectSheet(styles)(translate("repos")(ChangesetDetails));
