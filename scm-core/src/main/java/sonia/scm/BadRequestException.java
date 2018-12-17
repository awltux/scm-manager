package sonia.scm;

import java.util.List;

public abstract class BadRequestException extends ExceptionWithContext {
  public BadRequestException(List<ContextEntry> context, String message) {
    super(context, message);
  }
}
