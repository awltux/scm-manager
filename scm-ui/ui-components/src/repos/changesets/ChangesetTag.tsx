import React from "react";
import { Tag } from "@scm-manager/ui-types";
import ChangesetTagBase from "./ChangesetTagBase";

type Props = {
  tag: Tag;
};

class ChangesetTag extends React.Component<Props> {
  render() {
    const { tag } = this.props;
    return <ChangesetTagBase icon="tag" label={tag.name} />;
  }
}

export default ChangesetTag;
