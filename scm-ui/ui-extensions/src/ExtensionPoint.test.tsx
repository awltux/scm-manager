import React from "react";
import ExtensionPoint from "./ExtensionPoint";
import { shallow, mount } from "enzyme";
import "@scm-manager/ui-tests/enzyme";
import binder from "./binder";

jest.mock("./binder");

const mockedBinder = binder as jest.Mocked<typeof binder>;

describe("ExtensionPoint test", () => {
  beforeEach(() => {
    mockedBinder.hasExtension.mockReset();
    mockedBinder.getExtension.mockReset();
    mockedBinder.getExtensions.mockReset();
  });

  it("should render nothing, if no extension was bound", () => {
    mockedBinder.hasExtension.mockReturnValue(true);
    mockedBinder.getExtensions.mockReturnValue([]);
    const rendered = shallow(<ExtensionPoint name="something.special" />);
    expect(rendered.text()).toBe("");
  });

  it("should render the given component", () => {
    const label = () => {
      return <label>Extension One</label>;
    };
    mockedBinder.hasExtension.mockReturnValue(true);
    mockedBinder.getExtension.mockReturnValue(label);

    const rendered = mount(<ExtensionPoint name="something.special" />);
    expect(rendered.text()).toBe("Extension One");
  });

  it("should render the given components", () => {
    const labelOne = () => {
      return <label>Extension One</label>;
    };
    const labelTwo = () => {
      return <label>Extension Two</label>;
    };

    mockedBinder.hasExtension.mockReturnValue(true);
    mockedBinder.getExtensions.mockReturnValue([labelOne, labelTwo]);

    const rendered = mount(<ExtensionPoint name="something.special" renderAll={true} />);
    const text = rendered.text();
    expect(text).toContain("Extension One");
    expect(text).toContain("Extension Two");
  });

  it("should render the given component, with the given props", () => {
    type Props = {
      value: string;
    };

    const label = (props: Props) => {
      return <label>{props.value}</label>;
    };

    mockedBinder.hasExtension.mockReturnValue(true);
    mockedBinder.getExtension.mockReturnValue(label);

    const rendered = mount(
      <ExtensionPoint
        name="something.special"
        props={{
          value: "Awesome"
        }}
      />
    );
    const text = rendered.text();
    expect(text).toContain("Awesome");
  });

  it("should render children, if no extension is bound", () => {
    const rendered = mount(
      <ExtensionPoint name="something.special">
        <p>Cool stuff</p>
      </ExtensionPoint>
    );
    const text = rendered.text();
    expect(text).toContain("Cool stuff");
  });

  it("should not render children, if an extension was bound", () => {
    const label = () => {
      return <label>Bound Extension</label>;
    };

    mockedBinder.hasExtension.mockReturnValue(true);
    mockedBinder.getExtension.mockReturnValue(label);

    const rendered = mount(
      <ExtensionPoint name="something.special">
        <p>Cool stuff</p>
      </ExtensionPoint>
    );
    const text = rendered.text();
    expect(text).toContain("Bound Extension");
  });

  it("should pass the context of the parent component", () => {
    const UserContext = React.createContext({
      name: "anonymous"
    });

    type HelloProps = {
      name: string;
    };

    const Hello = (props: HelloProps) => {
      return <label>Hello {props.name}</label>;
    };

    const HelloUser = () => {
      return <UserContext.Consumer>{({ name }) => <Hello name={name} />}</UserContext.Consumer>;
    };

    mockedBinder.hasExtension.mockReturnValue(true);
    mockedBinder.getExtension.mockReturnValue(HelloUser);

    const App = () => {
      return (
        <UserContext.Provider
          value={{
            name: "Trillian"
          }}
        >
          <ExtensionPoint name="hello" />
        </UserContext.Provider>
      );
    };

    const rendered = mount(<App />);
    const text = rendered.text();
    expect(text).toBe("Hello Trillian");
  });

  it("should not render nothing without extension and without default", () => {
    mockedBinder.hasExtension.mockReturnValue(false);

    const rendered = mount(<ExtensionPoint name="something.special" />);
    const text = rendered.text();
    expect(text).toBe("");
  });
});
