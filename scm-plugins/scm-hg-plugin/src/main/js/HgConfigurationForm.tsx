import React from "react";
import { WithTranslation, withTranslation } from "react-i18next";
import { Links } from "@scm-manager/ui-types";
import { InputField, Checkbox } from "@scm-manager/ui-components";

type Configuration = {
  hgBinary: string;
  pythonBinary: string;
  pythonPath?: string;
  encoding: string;
  useOptimizedBytecode: boolean;
  showRevisionInId: boolean;
  disableHookSSLValidation: boolean;
  enableHttpPostArgs: boolean;
  _links: Links;
};

type Props = WithTranslation & {
  initialConfiguration: Configuration;
  readOnly: boolean;

  onConfigurationChange: (p1: Configuration, p2: boolean) => void;
};

type State = Configuration & {
  validationErrors: string[];
};

class HgConfigurationForm extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      ...props.initialConfiguration,
      validationErrors: []
    };
  }

  updateValidationStatus = () => {
    const requiredFields = ["hgBinary", "pythonBinary", "encoding"];

    const validationErrors = [];
    for (const field of requiredFields) {
      // @ts-ignore
      if (!this.state[field]) {
        validationErrors.push(field);
      }
    }

    this.setState({
      validationErrors
    });

    return validationErrors.length === 0;
  };

  hasValidationError = (name: string) => {
    return this.state.validationErrors.indexOf(name) >= 0;
  };

  handleChange = (value: string | boolean, name?: string) => {
    if (!name) {
      throw new Error("name not set");
    }
    this.setState(
      // @ts-ignore
      {
        [name]: value
      },
      () => this.props.onConfigurationChange(this.state, this.updateValidationStatus())
    );
  };

  inputField = (name: string) => {
    const { readOnly, t } = this.props;
    return (
      <div className="column is-half">
        <InputField
          name={name}
          label={t("scm-hg-plugin.config." + name)}
          helpText={t("scm-hg-plugin.config." + name + "HelpText")}
          // @ts-ignore
          value={this.state[name]}
          onChange={this.handleChange}
          validationError={this.hasValidationError(name)}
          errorMessage={t("scm-hg-plugin.config.required")}
          disabled={readOnly}
        />
      </div>
    );
  };

  checkbox = (name: string) => {
    const { readOnly, t } = this.props;
    return (
      <Checkbox
        name={name}
        label={t("scm-hg-plugin.config." + name)}
        helpText={t("scm-hg-plugin.config." + name + "HelpText")}
        // @ts-ignore
        checked={this.state[name]}
        onChange={this.handleChange}
        disabled={readOnly}
      />
    );
  };

  render() {
    return (
      <div className="columns is-multiline">
        {this.inputField("hgBinary")}
        {this.inputField("pythonBinary")}
        {this.inputField("pythonPath")}
        {this.inputField("encoding")}
        <div className="column is-half">
          {this.checkbox("useOptimizedBytecode")}
          {this.checkbox("showRevisionInId")}
        </div>
        <div className="column is-half">
          {this.checkbox("disableHookSSLValidation")}
          {this.checkbox("enableHttpPostArgs")}
        </div>
      </div>
    );
  }
}

export default withTranslation("plugins")(HgConfigurationForm);
