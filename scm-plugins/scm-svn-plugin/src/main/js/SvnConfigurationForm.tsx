import React from "react";
import { withTranslation, WithTranslation } from "react-i18next";
import { Links } from "@scm-manager/ui-types";
import { Checkbox, Select } from "@scm-manager/ui-components";

type Configuration = {
  compatibility: string;
  enabledGZip: boolean;
  _links: Links;
};

type Props = WithTranslation & {
  initialConfiguration: Configuration;
  readOnly: boolean;

  onConfigurationChange: (p1: Configuration, p2: boolean) => void;
};

type State = Configuration;

class SvnConfigurationForm extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      ...props.initialConfiguration
    };
  }

  handleChange = (value: any, name?: string) => {
    if (!name) {
      throw new Error("required name not set");
    }
    this.setState(
      // @ts-ignore
      {
        [name]: value
      },
      () => this.props.onConfigurationChange(this.state, true)
    );
  };

  compatibilityOptions = (values: string[]) => {
    const options = [];
    for (const value of values) {
      options.push(this.compatibilityOption(value));
    }
    return options;
  };

  compatibilityOption = (value: string) => {
    return {
      value,
      label: this.props.t("scm-svn-plugin.config.compatibility-values." + value.toLowerCase())
    };
  };

  render() {
    const { readOnly, t } = this.props;
    const compatibilityOptions = this.compatibilityOptions(["NONE", "PRE14", "PRE15", "PRE16", "PRE17", "WITH17"]);

    return (
      <>
        <Select
          name="compatibility"
          label={t("scm-svn-plugin.config.compatibility")}
          helpText={t("scm-svn-plugin.config.compatibilityHelpText")}
          value={this.state.compatibility}
          options={compatibilityOptions}
          onChange={this.handleChange}
        />
        <Checkbox
          name="enabledGZip"
          label={t("scm-svn-plugin.config.enabledGZip")}
          helpText={t("scm-svn-plugin.config.enabledGZipHelpText")}
          checked={this.state.enabledGZip}
          onChange={this.handleChange}
          disabled={readOnly}
        />
      </>
    );
  }
}

export default withTranslation("plugins")(SvnConfigurationForm);
