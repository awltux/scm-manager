import * as diffs from "./diffs";

import {
  File,
  FileChangeType,
  Hunk,
  Change,
  ChangeType,
  BaseContext,
  AnnotationFactory,
  AnnotationFactoryContext,
  DiffEventHandler,
  DiffEventContext
} from "./DiffTypes";

export { diffs };

export * from "./changesets";

export { default as Diff } from "./Diff";
export { default as DiffFile } from "./DiffFile";
export { default as DiffButton } from "./DiffButton";
export { default as LoadingDiff } from "./LoadingDiff";
export { DefaultCollapsed, DefaultCollapsedFunction } from "./defaultCollapsed";

export {
  File,
  FileChangeType,
  Hunk,
  Change,
  ChangeType,
  BaseContext,
  AnnotationFactory,
  AnnotationFactoryContext,
  DiffEventHandler,
  DiffEventContext
};
