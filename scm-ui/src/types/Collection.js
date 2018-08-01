// @flow
import type { Links } from "./hal";

export type Collection = {
  _embedded: Object,
  _links: Links
};

export type PagedCollection = Collection & {
  page: number,
  pageTotal: number
};
