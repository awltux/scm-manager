import * as types from "./types";

import { apiClient } from "@scm-manager/ui-components";
import { Action, IndexResources, Link } from "@scm-manager/ui-types";
import { isPending } from "./pending";
import { getFailure } from "./failure";

// Action

export const FETCH_INDEXRESOURCES = "scm/INDEXRESOURCES";
export const FETCH_INDEXRESOURCES_PENDING = `${FETCH_INDEXRESOURCES}_${types.PENDING_SUFFIX}`;
export const FETCH_INDEXRESOURCES_SUCCESS = `${FETCH_INDEXRESOURCES}_${types.SUCCESS_SUFFIX}`;
export const FETCH_INDEXRESOURCES_FAILURE = `${FETCH_INDEXRESOURCES}_${types.FAILURE_SUFFIX}`;

const INDEX_RESOURCES_LINK = "/";

export const callFetchIndexResources = (): Promise<IndexResources> => {
  return apiClient.get(INDEX_RESOURCES_LINK).then(response => {
    return response.json();
  });
};

export function fetchIndexResources() {
  return function(dispatch: any) {
    dispatch(fetchIndexResourcesPending());
    return callFetchIndexResources()
      .then(resources => {
        dispatch(fetchIndexResourcesSuccess(resources));
      })
      .catch(err => {
        dispatch(fetchIndexResourcesFailure(err));
      });
  };
}

export function fetchIndexResourcesPending(): Action {
  return {
    type: FETCH_INDEXRESOURCES_PENDING
  };
}

export function fetchIndexResourcesSuccess(resources: IndexResources): Action {
  return {
    type: FETCH_INDEXRESOURCES_SUCCESS,
    payload: resources
  };
}

export function fetchIndexResourcesFailure(err: Error): Action {
  return {
    type: FETCH_INDEXRESOURCES_FAILURE,
    payload: err
  };
}

// reducer
export default function reducer(
  state: object = {},
  action: Action = {
    type: "UNKNOWN"
  }
): object {
  if (!action.payload) {
    return state;
  }

  switch (action.type) {
    case FETCH_INDEXRESOURCES_SUCCESS:
      return {
        ...state,
        version: action.payload.version,
        links: action.payload._links
      };
    default:
      return state;
  }
}

// selectors

export function isFetchIndexResourcesPending(state: object) {
  return isPending(state, FETCH_INDEXRESOURCES);
}

export function getFetchIndexResourcesFailure(state: object) {
  return getFailure(state, FETCH_INDEXRESOURCES);
}

export function getLinks(state: object) {
  return state.indexResources.links;
}

export function getLink(state: object, name: string) {
  if (state.indexResources.links && state.indexResources.links[name]) {
    return state.indexResources.links[name].href;
  }
}

export function getLinkCollection(state: object, name: string): Link[] {
  if (state.indexResources.links && state.indexResources.links[name]) {
    return state.indexResources.links[name];
  }
  return [];
}

export function getAppVersion(state: object) {
  return state.indexResources.version;
}

export function getUiPluginsLink(state: object) {
  return getLink(state, "uiPlugins");
}

export function getAvailablePluginsLink(state: object) {
  return getLink(state, "availablePlugins");
}

export function getInstalledPluginsLink(state: object) {
  return getLink(state, "installedPlugins");
}

export function getPendingPluginsLink(state: object) {
  return getLink(state, "pendingPlugins");
}

export function getMeLink(state: object) {
  return getLink(state, "me");
}

export function getLogoutLink(state: object) {
  return getLink(state, "logout");
}

export function getLoginLink(state: object) {
  return getLink(state, "login");
}

export function getUsersLink(state: object) {
  return getLink(state, "users");
}

export function getRepositoryRolesLink(state: object) {
  return getLink(state, "repositoryRoles");
}

export function getRepositoryVerbsLink(state: object) {
  return getLink(state, "repositoryVerbs");
}

export function getGroupsLink(state: object) {
  return getLink(state, "groups");
}

export function getConfigLink(state: object) {
  return getLink(state, "config");
}

export function getRepositoriesLink(state: object) {
  return getLink(state, "repositories");
}

export function getHgConfigLink(state: object) {
  return getLink(state, "hgConfig");
}

export function getGitConfigLink(state: object) {
  return getLink(state, "gitConfig");
}

export function getSvnConfigLink(state: object) {
  return getLink(state, "svnConfig");
}

export function getLoginInfoLink(state: object) {
  return getLink(state, "loginInfo");
}

export function getUserAutoCompleteLink(state: object): string {
  const link = getLinkCollection(state, "autocomplete").find(i => i.name === "users");
  if (link) {
    return link.href;
  }
  return "";
}

export function getGroupAutoCompleteLink(state: object): string {
  const link = getLinkCollection(state, "autocomplete").find(i => i.name === "groups");
  if (link) {
    return link.href;
  }
  return "";
}
