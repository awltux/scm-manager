package sonia.scm.api.v2.resources;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Strings;

import javax.ws.rs.FormParam;
import java.util.List;

public class AuthenticationRequestDto {

  @FormParam("grant_type")
  @JsonProperty("grant_type")
  private String grantType;

  @FormParam("username")
  private String username;

  @FormParam("password")
  private String password;

  @FormParam("cookie")
  private boolean cookie;

  @FormParam("scope")
  private List<String> scope;

  public String getGrantType() {
    return grantType;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public boolean isCookie() {
    return cookie;
  }

  public List<String> getScope() {
    return scope;
  }

  public boolean isValid() {
    // password is currently the only valid grant_type
    return "password".equals(grantType) && !Strings.isNullOrEmpty(username) && !Strings.isNullOrEmpty(password);
  }
}
