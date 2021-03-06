import React, { ReactNode } from "react";
import Button from "./Button";
import { storiesOf } from "@storybook/react";
import styled from "styled-components";
import AddButton from "./AddButton";
import CreateButton from "./CreateButton";
import DeleteButton from "./DeleteButton";
import DownloadButton from "./DownloadButton";
import EditButton from "./EditButton";
import SubmitButton from "./SubmitButton";
import { ReactElement } from "react";

const colors = ["primary", "link", "info", "success", "warning", "danger", "white", "light", "dark", "black", "text"];

const Spacing = styled.div`
  padding: 1em;
`;

const SpacingDecorator = (story: () => ReactNode) => <Spacing>{story()}</Spacing>;

storiesOf("Buttons|Button", module)
  .add("Colors", () => (
    <div>
      {colors.map(color => (
        <Spacing key={color}>
          <Button color={color} label={color} />
        </Spacing>
      ))}
    </div>
  ))
  .add("Loading", () => (
    <Spacing>
      <Button color={"primary"} loading={true}>
        Loading Button
      </Button>
    </Spacing>
  ))
  .add("Disabled", () => (
    <div>
      {colors.map(color => (
        <Spacing key={color}>
          <Button color={color} label={color} disabled={true} />
        </Spacing>
      ))}
    </div>
  ));

const buttonStory = (name: string, storyFn: () => ReactElement) => {
  return storiesOf("Buttons|" + name, module)
    .addDecorator(SpacingDecorator)
    .add("Default", storyFn);
};
buttonStory("AddButton", () => <AddButton>Add</AddButton>);
buttonStory("CreateButton", () => <CreateButton>Create</CreateButton>);
buttonStory("DeleteButton", () => <DeleteButton>Delete</DeleteButton>);
buttonStory("DownloadButton", () => <DownloadButton displayName="Download" disabled={false} url="" />).add(
  "Disabled",
  () => <DownloadButton displayName="Download" disabled={true} url="" />
);
buttonStory("EditButton", () => <EditButton>Edit</EditButton>);
buttonStory("SubmitButton", () => <SubmitButton>Submit</SubmitButton>);
