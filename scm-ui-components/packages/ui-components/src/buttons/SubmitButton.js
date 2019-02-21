//@flow
import React from "react";
import Button, { type ButtonProps } from "./Button";

class SubmitButton extends React.Component<ButtonProps> {
  render() {
    const { action } = this.props;
    return (
      <Button
        type="submit"
        color="primary"
        {...this.props}
        action={(event) => {
          if (action) {
            action(event)
          }
          window.scrollTo(0, 0);
        }}
      />
    );
  }
}

export default SubmitButton;