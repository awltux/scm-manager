//@flow
import type {Collection, Links} from "./hal";
import type {Tag} from "./Tags";
import type {Branch} from "./Branches";

export type Changeset = Collection & {
  id: string,
  date: Date,
  author: {
    name: string,
    mail?: string
  },
  description: string,
  _links: Links,
  _embedded: {
    tags?: Tag[],
    branches?: Branch[],
    parents?: ParentChangeset[]
  };
}

export type ParentChangeset = {
  id: string,
  _links: Links
}
