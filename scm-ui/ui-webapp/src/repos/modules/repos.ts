import { apiClient } from "@scm-manager/ui-components";
import * as types from "../../modules/types";
import { Action, Repository, RepositoryCollection } from "@scm-manager/ui-types";
import { isPending } from "../../modules/pending";
import { getFailure } from "../../modules/failure";

export const FETCH_REPOS = "scm/repos/FETCH_REPOS";
export const FETCH_REPOS_PENDING = `${FETCH_REPOS}_${types.PENDING_SUFFIX}`;
export const FETCH_REPOS_SUCCESS = `${FETCH_REPOS}_${types.SUCCESS_SUFFIX}`;
export const FETCH_REPOS_FAILURE = `${FETCH_REPOS}_${types.FAILURE_SUFFIX}`;

export const FETCH_REPO = "scm/repos/FETCH_REPO";
export const FETCH_REPO_PENDING = `${FETCH_REPO}_${types.PENDING_SUFFIX}`;
export const FETCH_REPO_SUCCESS = `${FETCH_REPO}_${types.SUCCESS_SUFFIX}`;
export const FETCH_REPO_FAILURE = `${FETCH_REPO}_${types.FAILURE_SUFFIX}`;

export const CREATE_REPO = "scm/repos/CREATE_REPO";
export const CREATE_REPO_PENDING = `${CREATE_REPO}_${types.PENDING_SUFFIX}`;
export const CREATE_REPO_SUCCESS = `${CREATE_REPO}_${types.SUCCESS_SUFFIX}`;
export const CREATE_REPO_FAILURE = `${CREATE_REPO}_${types.FAILURE_SUFFIX}`;
export const CREATE_REPO_RESET = `${CREATE_REPO}_${types.RESET_SUFFIX}`;

export const MODIFY_REPO = "scm/repos/MODIFY_REPO";
export const MODIFY_REPO_PENDING = `${MODIFY_REPO}_${types.PENDING_SUFFIX}`;
export const MODIFY_REPO_SUCCESS = `${MODIFY_REPO}_${types.SUCCESS_SUFFIX}`;
export const MODIFY_REPO_FAILURE = `${MODIFY_REPO}_${types.FAILURE_SUFFIX}`;
export const MODIFY_REPO_RESET = `${MODIFY_REPO}_${types.RESET_SUFFIX}`;

export const DELETE_REPO = "scm/repos/DELETE_REPO";
export const DELETE_REPO_PENDING = `${DELETE_REPO}_${types.PENDING_SUFFIX}`;
export const DELETE_REPO_SUCCESS = `${DELETE_REPO}_${types.SUCCESS_SUFFIX}`;
export const DELETE_REPO_FAILURE = `${DELETE_REPO}_${types.FAILURE_SUFFIX}`;

const CONTENT_TYPE = "application/vnd.scmm-repository+json;v=2";

// fetch repos

const SORT_BY = "sortBy=namespaceAndName";

export function fetchRepos(link: string) {
  return fetchReposByLink(link);
}

export function fetchReposByPage(link: string, page: number, filter?: string) {
  if (filter) {
    return fetchReposByLink(`${link}?page=${page - 1}&q=${decodeURIComponent(filter)}`);
  }
  return fetchReposByLink(`${link}?page=${page - 1}`);
}

function appendSortByLink(url: string) {
  if (url.includes(SORT_BY)) {
    return url;
  }
  let urlWithSortBy = url;
  if (url.includes("?")) {
    urlWithSortBy += "&";
  } else {
    urlWithSortBy += "?";
  }
  return urlWithSortBy + SORT_BY;
}

export function fetchReposByLink(link: string) {
  const url = appendSortByLink(link);
  return function(dispatch: any) {
    dispatch(fetchReposPending());
    return apiClient
      .get(url)
      .then(response => response.json())
      .then(repositories => {
        dispatch(fetchReposSuccess(repositories));
      })
      .catch(err => {
        dispatch(fetchReposFailure(err));
      });
  };
}

export function fetchReposPending(): Action {
  return {
    type: FETCH_REPOS_PENDING
  };
}

export function fetchReposSuccess(repositories: RepositoryCollection): Action {
  return {
    type: FETCH_REPOS_SUCCESS,
    payload: repositories
  };
}

export function fetchReposFailure(err: Error): Action {
  return {
    type: FETCH_REPOS_FAILURE,
    payload: err
  };
}

// fetch repo
export function fetchRepoByLink(repo: Repository) {
  return fetchRepo(repo._links.self.href, repo.namespace, repo.name);
}

export function fetchRepoByName(link: string, namespace: string, name: string) {
  const repoUrl = link.endsWith("/") ? link : link + "/";
  return fetchRepo(`${repoUrl}${namespace}/${name}`, namespace, name);
}

function fetchRepo(link: string, namespace: string, name: string) {
  return function(dispatch: any) {
    dispatch(fetchRepoPending(namespace, name));
    return apiClient
      .get(link)
      .then(response => response.json())
      .then(repository => {
        dispatch(fetchRepoSuccess(repository));
      })
      .catch(err => {
        dispatch(fetchRepoFailure(namespace, name, err));
      });
  };
}

export function fetchRepoPending(namespace: string, name: string): Action {
  return {
    type: FETCH_REPO_PENDING,
    payload: {
      namespace,
      name
    },
    itemId: namespace + "/" + name
  };
}

export function fetchRepoSuccess(repository: Repository): Action {
  return {
    type: FETCH_REPO_SUCCESS,
    payload: repository,
    itemId: createIdentifier(repository)
  };
}

export function fetchRepoFailure(namespace: string, name: string, error: Error): Action {
  return {
    type: FETCH_REPO_FAILURE,
    payload: {
      namespace,
      name,
      error
    },
    itemId: namespace + "/" + name
  };
}

// create repo

export function createRepo(link: string, repository: Repository, initRepository: boolean, callback?: (repo: Repository) => void) {
  return function(dispatch: any) {
    dispatch(createRepoPending());
    const repoLink = initRepository ? link + "?initialize=true" : link;
    return apiClient
      .post(repoLink, repository, CONTENT_TYPE)
      .then(response => {
        const location = response.headers.get("Location");
        dispatch(createRepoSuccess());
        return apiClient.get(location);
      })
      .then(response => response.json())
      .then(response => {
        if (callback) {
          callback(response);
        }
      })
      .catch(err => {
        dispatch(createRepoFailure(err));
      });
  };
}

export function createRepoPending(): Action {
  return {
    type: CREATE_REPO_PENDING
  };
}

export function createRepoSuccess(): Action {
  return {
    type: CREATE_REPO_SUCCESS
  };
}

export function createRepoFailure(err: Error): Action {
  return {
    type: CREATE_REPO_FAILURE,
    payload: err
  };
}

export function createRepoReset(): Action {
  return {
    type: CREATE_REPO_RESET
  };
}

// modify

export function modifyRepo(repository: Repository, callback?: () => void) {
  return function(dispatch: any) {
    dispatch(modifyRepoPending(repository));

    return apiClient
      .put(repository._links.update.href, repository, CONTENT_TYPE)
      .then(() => {
        dispatch(modifyRepoSuccess(repository));
        if (callback) {
          callback();
        }
      })
      .then(() => {
        dispatch(fetchRepoByLink(repository));
      })
      .catch(error => {
        dispatch(modifyRepoFailure(repository, error));
      });
  };
}

export function modifyRepoPending(repository: Repository): Action {
  return {
    type: MODIFY_REPO_PENDING,
    payload: repository,
    itemId: createIdentifier(repository)
  };
}

export function modifyRepoSuccess(repository: Repository): Action {
  return {
    type: MODIFY_REPO_SUCCESS,
    payload: repository,
    itemId: createIdentifier(repository)
  };
}

export function modifyRepoFailure(repository: Repository, error: Error): Action {
  return {
    type: MODIFY_REPO_FAILURE,
    payload: {
      error,
      repository
    },
    itemId: createIdentifier(repository)
  };
}

export function modifyRepoReset(repository: Repository): Action {
  return {
    type: MODIFY_REPO_RESET,
    payload: {
      repository
    },
    itemId: createIdentifier(repository)
  };
}

// delete

export function deleteRepo(repository: Repository, callback?: () => void) {
  return function(dispatch: any) {
    dispatch(deleteRepoPending(repository));
    return apiClient
      .delete(repository._links.delete.href)
      .then(() => {
        dispatch(deleteRepoSuccess(repository));
        if (callback) {
          callback();
        }
      })
      .catch(err => {
        dispatch(deleteRepoFailure(repository, err));
      });
  };
}

export function deleteRepoPending(repository: Repository): Action {
  return {
    type: DELETE_REPO_PENDING,
    payload: repository,
    itemId: createIdentifier(repository)
  };
}

export function deleteRepoSuccess(repository: Repository): Action {
  return {
    type: DELETE_REPO_SUCCESS,
    payload: repository,
    itemId: createIdentifier(repository)
  };
}

export function deleteRepoFailure(repository: Repository, error: Error): Action {
  return {
    type: DELETE_REPO_FAILURE,
    payload: {
      error,
      repository
    },
    itemId: createIdentifier(repository)
  };
}

// reducer

function createIdentifier(repository: Repository) {
  return repository.namespace + "/" + repository.name;
}

function normalizeByNamespaceAndName(repositoryCollection: RepositoryCollection) {
  const names = [];
  const byNames = {};
  for (const repository of repositoryCollection._embedded.repositories) {
    const identifier = createIdentifier(repository);
    names.push(identifier);
    byNames[identifier] = repository;
  }
  return {
    list: {
      ...repositoryCollection,
      _embedded: {
        repositories: names
      }
    },
    byNames: byNames
  };
}

const reducerByNames = (state: object, repository: Repository) => {
  const identifier = createIdentifier(repository);
  return {
    ...state,
    byNames: {
      ...state.byNames,
      [identifier]: repository
    }
  };
};

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
    case FETCH_REPOS_SUCCESS:
      return normalizeByNamespaceAndName(action.payload);
    case FETCH_REPO_SUCCESS:
      return reducerByNames(state, action.payload);
    default:
      return state;
  }
}

// selectors

export function getRepositoryCollection(state: object) {
  if (state.repos && state.repos.list && state.repos.byNames) {
    const repositories = [];
    for (const repositoryName of state.repos.list._embedded.repositories) {
      repositories.push(state.repos.byNames[repositoryName]);
    }
    return {
      ...state.repos.list,
      _embedded: {
        repositories
      }
    };
  }
}

export function isFetchReposPending(state: object) {
  return isPending(state, FETCH_REPOS);
}

export function getFetchReposFailure(state: object) {
  return getFailure(state, FETCH_REPOS);
}

export function getRepository(state: object, namespace: string, name: string) {
  if (state.repos && state.repos.byNames) {
    return state.repos.byNames[namespace + "/" + name];
  }
}

export function isFetchRepoPending(state: object, namespace: string, name: string) {
  return isPending(state, FETCH_REPO, namespace + "/" + name);
}

export function getFetchRepoFailure(state: object, namespace: string, name: string) {
  return getFailure(state, FETCH_REPO, namespace + "/" + name);
}

export function isAbleToCreateRepos(state: object) {
  return !!(state.repos && state.repos.list && state.repos.list._links && state.repos.list._links.create);
}

export function isCreateRepoPending(state: object) {
  return isPending(state, CREATE_REPO);
}

export function getCreateRepoFailure(state: object) {
  return getFailure(state, CREATE_REPO);
}

export function isModifyRepoPending(state: object, namespace: string, name: string) {
  return isPending(state, MODIFY_REPO, namespace + "/" + name);
}

export function getModifyRepoFailure(state: object, namespace: string, name: string) {
  return getFailure(state, MODIFY_REPO, namespace + "/" + name);
}

export function isDeleteRepoPending(state: object, namespace: string, name: string) {
  return isPending(state, DELETE_REPO, namespace + "/" + name);
}

export function getDeleteRepoFailure(state: object, namespace: string, name: string) {
  return getFailure(state, DELETE_REPO, namespace + "/" + name);
}

export function getPermissionsLink(state: object, namespace: string, name: string) {
  const repo = getRepository(state, namespace, name);
  return repo && repo._links ? repo._links.permissions.href : undefined;
}
