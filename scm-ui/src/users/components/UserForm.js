// @flow
import React from "react";
import { translate } from "react-i18next";
import type { User } from "@scm-manager/ui-types";
import {
  Checkbox,
  InputField,
  SubmitButton,
  validation as validator
} from "@scm-manager/ui-components";
import * as userValidator from "./userValidation";

type Props = {
  submitForm: User => void,
  user?: User,
  loading?: boolean,
  t: string => string
};

type State = {
  user: User,
  mailValidationError: boolean,
  nameValidationError: boolean,
  displayNameValidationError: boolean,
  passwordConfirmationError: boolean,
  validatePasswordError: boolean,
  validatePassword: string
};

class UserForm extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);

    this.state = {
      user: {
        name: "",
        displayName: "",
        mail: "",
        password: "",
        admin: false,
        active: false,
        _links: {}
      },
      mailValidationError: false,
      displayNameValidationError: false,
      nameValidationError: false,
      passwordConfirmationError: false,
      validatePasswordError: false,
      validatePassword: ""
    };
  }

  componentDidMount() {
    const { user } = this.props;
    if (user) {
      this.setState({ user: { ...user } });
    }
  }

  isFalsy(value) {
    if (!value) {
      return true;
    }
    return false;
  }

  isValid = () => {
    const user = this.state.user;
    return !(
      this.state.validatePasswordError ||
      this.state.nameValidationError ||
      this.state.mailValidationError ||
      this.state.passwordConfirmationError ||
      this.state.displayNameValidationError ||
      this.isFalsy(user.name) ||
      this.isFalsy(user.displayName)
    );
  };

  submit = (event: Event) => {
    event.preventDefault();
    if (this.isValid()) {
      this.props.submitForm(this.state.user);
    }
  };

  render() {
    const { loading, t } = this.props;
    const user = this.state.user;
    let nameField = null;
    let passwordFields = null;
    if (!this.props.user) {
      nameField = (
        <InputField
          label={t("user.name")}
          onChange={this.handleUsernameChange}
          value={user ? user.name : ""}
          validationError={this.state.nameValidationError}
          errorMessage={t("validation.name-invalid")}
          helpText={t("help.usernameHelpText")}
        />
      );
      if (!this.props.user) {
        passwordFields = (
          <>
            <InputField
              label={t("user.password")}
              type="password"
              onChange={this.handlePasswordChange}
              value={user ? user.password : ""}
              validationError={this.state.validatePasswordError}
              errorMessage={t("validation.password-invalid")}
              helpText={t("help.passwordHelpText")}
            />
            <InputField
              label={t("validation.validatePassword")}
              type="password"
              onChange={this.handlePasswordValidationChange}
              value={this.state ? this.state.validatePassword : ""}
              validationError={this.state.passwordConfirmationError}
              errorMessage={t("validation.passwordValidation-invalid")}
              helpText={t("help.passwordConfirmHelpText")}
            />
          </>
        );
      }
    }
    return (
      <form onSubmit={this.submit}>
        {nameField}
        <InputField
          label={t("user.displayName")}
          onChange={this.handleDisplayNameChange}
          value={user ? user.displayName : ""}
          validationError={this.state.displayNameValidationError}
          errorMessage={t("validation.displayname-invalid")}
          helpText={t("help.displayNameHelpText")}
        />
        <InputField
          label={t("user.mail")}
          onChange={this.handleEmailChange}
          value={user ? user.mail : ""}
          validationError={this.state.mailValidationError}
          errorMessage={t("validation.mail-invalid")}
          helpText={t("help.mailHelpText")}
        />
        {passwordFields}
        <Checkbox
          label={t("user.admin")}
          onChange={this.handleAdminChange}
          checked={user ? user.admin : false}
          helpText={t("help.adminHelpText")}
        />
        <Checkbox
          label={t("user.active")}
          onChange={this.handleActiveChange}
          checked={user ? user.active : false}
          helpText={t("help.activeHelpText")}
        />
        <SubmitButton
          disabled={!this.isValid()}
          loading={loading}
          label={t("user-form.submit")}
        />
      </form>
    );
  }

  handleUsernameChange = (name: string) => {
    this.setState({
      nameValidationError: !validator.isNameValid(name),
      user: { ...this.state.user, name }
    });
  };

  handleDisplayNameChange = (displayName: string) => {
    this.setState({
      displayNameValidationError: !userValidator.isDisplayNameValid(
        displayName
      ),
      user: { ...this.state.user, displayName }
    });
  };

  handleEmailChange = (mail: string) => {
    this.setState({
      mailValidationError: !validator.isMailValid(mail),
      user: { ...this.state.user, mail }
    });
  };

  handlePasswordChange = (password: string) => {
    const validatePasswordError = !this.checkPasswords(
      password,
      this.state.validatePassword
    );
    this.setState({
      validatePasswordError: !userValidator.isPasswordValid(password),
      passwordConfirmationError: validatePasswordError,
      user: { ...this.state.user, password }
    });
  };

  handlePasswordValidationChange = (validatePassword: string) => {
    const validatePasswordError = this.checkPasswords(
      this.state.user.password,
      validatePassword
    );
    this.setState({
      validatePassword,
      passwordConfirmationError: !validatePasswordError
    });
  };

  checkPasswords = (password1: string, password2: string) => {
    return password1 === password2;
  };

  handleAdminChange = (admin: boolean) => {
    this.setState({ user: { ...this.state.user, admin } });
  };

  handleActiveChange = (active: boolean) => {
    this.setState({ user: { ...this.state.user, active } });
  };
}

export default translate("users")(UserForm);
