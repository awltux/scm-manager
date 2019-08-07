// @flow
import React from "react";
import injectSheet from "react-jss";
import { AsyncCreatable, Async } from "react-select";
import classNames from "classnames";
import type { AutocompleteObject, SelectValue } from "@scm-manager/ui-types";
import LabelWithHelpIcon from "./forms/LabelWithHelpIcon";
import {translate} from "react-i18next";

type Props = {
  loadSuggestions: string => Promise<AutocompleteObject>,
  valueSelected: SelectValue => void,
  label: string,
  helpText?: string,
  value?: SelectValue,
  placeholder: string,
  loadingMessage: string,
  noOptionsMessage: string,
  creatable?: boolean,

  // context props
  classes: any
};

type State = {};

const styles = {
  zIndex: {
    zIndex: 5
  }
};

class Autocomplete extends React.Component<Props, State> {
  static defaultProps = {
    placeholder: "Type here",
    loadingMessage: "Loading...",
    noOptionsMessage: "No suggestion available"
  };

  handleInputChange = (newValue: SelectValue) => {
    this.props.valueSelected(newValue);
  };

  // We overwrite this to avoid running into a bug (https://github.com/JedWatson/react-select/issues/2944)
  isValidNewOption = (
    inputValue: string,
    selectValue: SelectValue,
    selectOptions: SelectValue[]
  ) => {
    const isNotDuplicated = !selectOptions
      .map(option => option.label)
      .includes(inputValue);
    const isNotEmpty = inputValue !== "";
    return isNotEmpty && isNotDuplicated;
  };

  render() {
    const {
      label,
      helpText,
      value,
      placeholder,
      loadingMessage,
      noOptionsMessage,
      loadSuggestions,
      creatable,
      classes
    } = this.props;
    return (
      <div className="field">
        <LabelWithHelpIcon label={label} helpText={helpText} />
        <div className={classNames("control", classes.zIndex)}>
          {creatable ? (
            <AsyncCreatable
              cacheOptions
              loadOptions={loadSuggestions}
              onChange={this.handleInputChange}
              value={value}
              placeholder={placeholder}
              loadingMessage={() => loadingMessage}
              noOptionsMessage={() => noOptionsMessage}
              isValidNewOption={this.isValidNewOption}
              onCreateOption={value => {
                this.handleInputChange({
                  label: value,
                  value: { id: value, displayName: value }
                });
              }}
            />
          ) : (
            <Async
              cacheOptions
              loadOptions={loadSuggestions}
              onChange={this.handleInputChange}
              value={value}
              placeholder={placeholder}
              loadingMessage={() => loadingMessage}
              noOptionsMessage={() => noOptionsMessage}
            />
          )}
        </div>
      </div>
    );
  }
}

export default injectSheet(styles)(Autocomplete);
