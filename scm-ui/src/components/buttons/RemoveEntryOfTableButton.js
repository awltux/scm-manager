//@flow
import React from "react";
import { DeleteButton } from ".";
import classNames from "classnames";

type Props = {
  entryname: string,
  removeEntry: string => void,
  disabled: boolean,
  label: string
};

type State = {};

class RemoveEntryOfTableButton extends React.Component<Props, State> {
  render() {
    const { label, entryname, removeEntry, disabled } = this.props;
    return (
      <div className={classNames("is-pulled-right")}>
        <DeleteButton
          label={label}
          action={(event: Event) => {
            event.preventDefault();
            removeEntry(entryname);
          }}
          disabled={disabled}
        />
      </div>
    );
  }
}

export default RemoveEntryOfTableButton;
