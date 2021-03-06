import { contextPath } from "./urls";
// @ts-ignore we have not types for event-source-polyfill
import { EventSourcePolyfill } from "event-source-polyfill";
import { createBackendError, ForbiddenError, isBackendError, UnauthorizedError, BackendErrorContent } from "./errors";

type SubscriptionEvent = {
  type: string;
};

type OpenEvent = SubscriptionEvent;

type ErrorEvent = SubscriptionEvent & {
  error: Error;
};

type MessageEvent = SubscriptionEvent & {
  data: string;
  lastEventId?: string;
};

type MessageListeners = {
  [eventType: string]: (event: MessageEvent) => void;
};

type SubscriptionContext = {
  onOpen?: OpenEvent;
  onMessage: MessageListeners;
  onError?: ErrorEvent;
};

type SubscriptionArgument = MessageListeners | SubscriptionContext;

type Cancel = () => void;

const sessionId = (
  Date.now().toString(36) +
  Math.random()
    .toString(36)
    .substr(2, 5)
).toUpperCase();

const extractXsrfTokenFromJwt = (jwt: string) => {
  const parts = jwt.split(".");
  if (parts.length === 3) {
    return JSON.parse(atob(parts[1])).xsrf;
  }
};

// @VisibleForTesting
export const extractXsrfTokenFromCookie = (cookieString?: string) => {
  if (cookieString) {
    const cookies = cookieString.split(";");
    for (const c of cookies) {
      const parts = c.trim().split("=");
      if (parts[0] === "X-Bearer-Token") {
        return extractXsrfTokenFromJwt(parts[1]);
      }
    }
  }
};

const extractXsrfToken = () => {
  return extractXsrfTokenFromCookie(document.cookie);
};

const createRequestHeaders = () => {
  const headers: { [key: string]: string } = {
    // disable caching for now
    Cache: "no-cache",
    // identify the request as ajax request
    "X-Requested-With": "XMLHttpRequest",
    // identify the web interface
    "X-SCM-Client": "WUI",
    // identify the window session
    "X-SCM-Session-ID": sessionId
  };

  const xsrf = extractXsrfToken();
  if (xsrf) {
    headers["X-XSRF-Token"] = xsrf;
  }
  return headers;
};

const applyFetchOptions: (p: RequestInit) => RequestInit = o => {
  if (o.headers) {
    o.headers = {
      ...createRequestHeaders()
    };
  } else {
    o.headers = createRequestHeaders();
  }
  o.credentials = "same-origin";
  return o;
};

function handleFailure(response: Response) {
  if (!response.ok) {
    if (isBackendError(response)) {
      return response.json().then((content: BackendErrorContent) => {
        throw createBackendError(content, response.status);
      });
    } else {
      if (response.status === 401) {
        throw new UnauthorizedError("Unauthorized", 401);
      } else if (response.status === 403) {
        throw new ForbiddenError("Forbidden", 403);
      }

      throw new Error("server returned status code " + response.status);
    }
  }
  return response;
}

export function createUrl(url: string) {
  if (url.includes("://")) {
    return url;
  }
  let urlWithStartingSlash = url;
  if (url.indexOf("/") !== 0) {
    urlWithStartingSlash = "/" + urlWithStartingSlash;
  }
  return `${contextPath}/api/v2${urlWithStartingSlash}`;
}

class ApiClient {
  get(url: string): Promise<Response> {
    return fetch(createUrl(url), applyFetchOptions({})).then(handleFailure);
  }

  post(url: string, payload?: any, contentType = "application/json", additionalHeaders: Record<string, string> = {}) {
    return this.httpRequestWithJSONBody("POST", url, contentType, additionalHeaders, payload);
  }

  postText(url: string, payload: string, additionalHeaders: Record<string, string> = {}) {
    return this.httpRequestWithTextBody("POST", url, additionalHeaders, payload);
  }

  putText(url: string, payload: string, additionalHeaders: Record<string, string> = {}) {
    return this.httpRequestWithTextBody("PUT", url, additionalHeaders, payload);
  }

  postBinary(url: string, fileAppender: (p: FormData) => void, additionalHeaders: Record<string, string> = {}) {
    const formData = new FormData();
    fileAppender(formData);

    const options: RequestInit = {
      method: "POST",
      body: formData,
      headers: additionalHeaders
    };
    return this.httpRequestWithBinaryBody(options, url);
  }

  put(url: string, payload: any, contentType = "application/json", additionalHeaders: Record<string, string> = {}) {
    return this.httpRequestWithJSONBody("PUT", url, contentType, additionalHeaders, payload);
  }

  head(url: string) {
    let options: RequestInit = {
      method: "HEAD"
    };
    options = applyFetchOptions(options);
    return fetch(createUrl(url), options).then(handleFailure);
  }

  delete(url: string): Promise<Response> {
    let options: RequestInit = {
      method: "DELETE"
    };
    options = applyFetchOptions(options);
    return fetch(createUrl(url), options).then(handleFailure);
  }

  httpRequestWithJSONBody(
    method: string,
    url: string,
    contentType: string,
    additionalHeaders: Record<string, string>,
    payload?: any
  ): Promise<Response> {
    const options: RequestInit = {
      method: method,
      headers: additionalHeaders
    };
    if (payload) {
      options.body = JSON.stringify(payload);
    }
    return this.httpRequestWithBinaryBody(options, url, contentType);
  }

  httpRequestWithTextBody(
    method: string,
    url: string,
    additionalHeaders: Record<string, string> = {},
    payload: string
  ) {
    const options: RequestInit = {
      method: method,
      headers: additionalHeaders
    };
    options.body = payload;
    return this.httpRequestWithBinaryBody(options, url, "text/plain");
  }

  httpRequestWithBinaryBody(options: RequestInit, url: string, contentType?: string) {
    options = applyFetchOptions(options);
    if (contentType) {
      if (!options.headers) {
        options.headers = {};
      }
      // @ts-ignore We are sure that here we only get headers of type {[name:string]: string}
      options.headers["Content-Type"] = contentType;
    }

    return fetch(createUrl(url), options).then(handleFailure);
  }

  subscribe(url: string, argument: SubscriptionArgument): Cancel {
    const es = new EventSourcePolyfill(createUrl(url), {
      withCredentials: true,
      headers: createRequestHeaders()
    });

    let listeners: MessageListeners;
    // type guard, to identify that argument is of type SubscriptionContext
    if ("onMessage" in argument) {
      listeners = (argument as SubscriptionContext).onMessage;
      if (argument.onError) {
        es.onerror = argument.onError;
      }
      if (argument.onOpen) {
        es.onopen = argument.onOpen;
      }
    } else {
      listeners = argument;
    }

    for (const type in listeners) {
      es.addEventListener(type, listeners[type]);
    }

    return () => es.close();
  }
}

export const apiClient = new ApiClient();
