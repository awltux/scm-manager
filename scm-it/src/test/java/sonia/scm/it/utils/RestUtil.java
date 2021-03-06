package sonia.scm.it.utils;

import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;

import java.net.URI;

import static java.net.URI.create;

public class RestUtil {

  public static final URI BASE_URL = create("http://localhost:8081/scm/");
  public static final URI REST_BASE_URL = BASE_URL.resolve("api/v2/");

  public static URI createResourceUrl(String path) {
    return REST_BASE_URL.resolve(path);
  }

  public static final String ADMIN_USERNAME = "scmadmin";
  public static final String ADMIN_PASSWORD = "scmadmin";

  public static RequestSpecification given() {
    return RestAssured.given()
      .auth().preemptive().basic(ADMIN_USERNAME, ADMIN_PASSWORD);
  }

  public static RequestSpecification given(String mediaType) {
    return given(mediaType, ADMIN_USERNAME, ADMIN_PASSWORD);
  }

  public static RequestSpecification given(String mediaType, String username, String password) {
    return givenAnonymous(mediaType)
      .auth().preemptive().basic(username, password);
  }

  public static RequestSpecification givenAnonymous(String mediaType) {
    return RestAssured.given()
      .contentType(mediaType)
      .accept(mediaType);
  }
}
