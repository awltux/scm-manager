package sonia.scm.user;

import sonia.scm.BadRequestException;
import sonia.scm.ContextEntry;

@SuppressWarnings("squid:MaximumInheritanceDepth") // exceptions have a deep inheritance depth themselves; therefore we accept this here
public class InvalidPasswordException extends BadRequestException {

  private static final String CODE = "8YR7aawFW1";

  public InvalidPasswordException(ContextEntry.ContextBuilder context) {
    super(context.build(), "The given old password does not match with the stored one.");
  }

  @Override
  public String getCode() {
    return CODE;
  }
}
