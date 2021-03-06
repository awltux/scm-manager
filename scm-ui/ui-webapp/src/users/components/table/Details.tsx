import React from "react";
import { WithTranslation, withTranslation } from "react-i18next";
import { User } from "@scm-manager/ui-types";
import { Checkbox, DateFromNow, MailLink } from "@scm-manager/ui-components";

type Props = WithTranslation & {
  user: User;
};

class Details extends React.Component<Props> {
  render() {
    const { user, t } = this.props;
    return (
      <table className="table">
        <tbody>
          <tr>
            <th>{t("user.name")}</th>
            <td>{user.name}</td>
          </tr>
          <tr>
            <th>{t("user.displayName")}</th>
            <td>{user.displayName}</td>
          </tr>
          <tr>
            <th>{t("user.mail")}</th>
            <td>
              <MailLink address={user.mail} />
            </td>
          </tr>
          <tr>
            <th>{t("user.active")}</th>
            <td>
              <Checkbox checked={user.active} />
            </td>
          </tr>
          <tr>
            <th>{t("user.type")}</th>
            <td>{user.type}</td>
          </tr>
          <tr>
            <th>{t("user.creationDate")}</th>
            <td>
              <DateFromNow date={user.creationDate} />
            </td>
          </tr>
          <tr>
            <th>{t("user.lastModified")}</th>
            <td>
              <DateFromNow date={user.lastModified} />
            </td>
          </tr>
        </tbody>
      </table>
    );
  }
}

export default withTranslation("users")(Details);
