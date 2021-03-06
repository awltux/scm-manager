import React, { useEffect, useState } from "react";
import { storiesOf } from "@storybook/react";
import Diff from "./Diff";
// @ts-ignore
import parser from "gitdiff-parser";
import simpleDiff from "../__resources__/Diff.simple";
import hunksDiff from "../__resources__/Diff.hunks";
import binaryDiff from "../__resources__/Diff.binary";
import { DiffEventContext, File } from "./DiffTypes";
import Toast from "../toast/Toast";
import { getPath } from "./diffs";
import DiffButton from "./DiffButton";
import styled from "styled-components";

const diffFiles = parser.parse(simpleDiff);

const Container = styled.div`
  padding: 2rem 6rem;
`;

storiesOf("Diff", module)
  .addDecorator(storyFn => <Container>{storyFn()}</Container>)
  .add("Default", () => <Diff diff={diffFiles} />)
  .add("Side-By-Side", () => <Diff diff={diffFiles} sideBySide={true} />)
  .add("Collapsed", () => <Diff diff={diffFiles} defaultCollapse={true} />)
  .add("File Controls", () => (
    <Diff
      diff={diffFiles}
      fileControlFactory={() => (
        <DiffButton
          tooltip="A skull and crossbones or death's head is a symbol consisting of a human skull and two long bones crossed together under or behind the skull. The design originates in the Late Middle Ages as a symbol of death and especially as a memento mori on tombstones."
          icon="skull-crossbones"
          onClick={() => alert("Arrrgggghhhh ...")}
        />
      )}
    />
  ))
  .add("File Annotation", () => (
    <Diff
      diff={diffFiles}
      fileAnnotationFactory={file => [<p key={file.newPath}>Custom File annotation for {file.newPath}</p>]}
    />
  ))
  .add("Line Annotation", () => (
    <Diff
      diff={diffFiles}
      annotationFactory={ctx => {
        return {
          N2: <p key="N2">Line Annotation</p>
        };
      }}
    />
  ))
  .add("OnClick", () => {
    const OnClickDemo = () => {
      const [changeId, setChangeId] = useState();
      useEffect(() => {
        const interval = setInterval(() => setChangeId(undefined), 2000);
        return () => clearInterval(interval);
      });
      const onClick = (context: DiffEventContext) => setChangeId(context.changeId);
      return (
        <>
          {changeId && <Toast type="info" title={"Change " + changeId} />}
          <Diff diff={diffFiles} onClick={onClick} />
        </>
      );
    };
    return <OnClickDemo />;
  })
  .add("Hunks", () => {
    const hunkDiffFiles = parser.parse(hunksDiff);
    return <Diff diff={hunkDiffFiles} />;
  })
  .add("Binaries", () => {
    const binaryDiffFiles = parser.parse(binaryDiff);
    return <Diff diff={binaryDiffFiles} />;
  })
  .add("SyntaxHighlighting", () => {
    const filesWithLanguage = diffFiles.map((file: File) => {
      const ext = getPath(file).split(".")[1];
      if (ext === "tsx") {
        file.language = "typescript";
      } else {
        file.language = ext;
      }
      return file;
    });
    return <Diff diff={filesWithLanguage} />;
  })
  .add("CollapsingWithFunction", () => (
    <Diff diff={diffFiles} defaultCollapse={(oldPath, newPath) => oldPath.endsWith(".java")} />
  ));
