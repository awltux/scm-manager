import React from "react";
import { WithTranslation, withTranslation } from "react-i18next";
import { RepositoryRole } from "@scm-manager/ui-types";
import AvailableVerbs from "./AvailableVerbs";

type Props = WithTranslation & {
  role: RepositoryRole;
};

class PermissionRoleDetailsTable extends React.Component<Props> {
  render() {
    const { role, t } = this.props;
    return (
      <table className="table content">
        <tbody>
          <tr>
            <th>{t("repositoryRole.name")}</th>
            <td>{role.name}</td>
          </tr>
          <tr>
            <th>{t("repositoryRole.type")}</th>
            <td>{role.type}</td>
          </tr>
          <tr>
            <th>{t("repositoryRole.verbs")}</th>
            <AvailableVerbs role={role} />
          </tr>
        </tbody>
      </table>
    );
  }
}

export default withTranslation("admin")(PermissionRoleDetailsTable);
