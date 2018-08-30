// @flow
import React from "react";
import { translate } from "react-i18next";
import { Checkbox, InputField } from "../../../components/forms/index";
import Subtitle from "../../../components/layout/Subtitle";

type Props = {
  baseUrl: string,
  forceBaseUrl: boolean,
  t: string => string,
  onChange: (boolean, any, string) => void,
  hasUpdatePermission: boolean
};

class BaseUrlSettings extends React.Component<Props> {
  render() {
    const { t, baseUrl, forceBaseUrl, hasUpdatePermission } = this.props;

    return (
      <div>
        <Subtitle subtitle={t("base-url-settings.name")} />
        <Checkbox
          checked={forceBaseUrl}
          label={t("base-url-settings.force-base-url")}
          onChange={this.handleForceBaseUrlChange}
          disabled={!hasUpdatePermission}
        />
        <InputField
          label={t("base-url-settings.base-url")}
          onChange={this.handleBaseUrlChange}
          value={baseUrl}
          disabled={!hasUpdatePermission}
        />
      </div>
    );
  }

  handleBaseUrlChange = (value: string) => {
    this.props.onChange(true, value, "baseUrl");
  };
  handleForceBaseUrlChange = (value: boolean) => {
    this.props.onChange(true, value, "forceBaseUrl");
  };
}

export default translate("config")(BaseUrlSettings);
