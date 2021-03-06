package sonia.scm.it.utils;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import java.util.regex.Pattern;

public class RegExMatcher extends BaseMatcher<String> {
  public static Matcher<String> matchesPattern(String pattern) {
    return new RegExMatcher(pattern);
  }

  private final String pattern;

  private RegExMatcher(String pattern) {
    this.pattern = pattern;
  }

  @Override
  public void describeTo(Description description) {
    description.appendText("matching to regex pattern \"" + pattern + "\"");
  }

  @Override
  public boolean matches(Object o) {
    return o != null && Pattern.compile(pattern).matcher(o.toString()).matches();
  }
}
