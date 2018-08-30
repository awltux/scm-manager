package sonia.scm.api.v2.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.sdorra.shiro.ShiroRule;
import com.github.sdorra.shiro.SubjectAware;
import com.google.common.collect.ImmutableList;
import de.otto.edison.hal.HalRepresentation;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.util.ThreadState;
import org.assertj.core.util.Lists;
import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.MockDispatcherFactory;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.jboss.resteasy.spi.HttpRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import sonia.scm.api.rest.AuthorizationExceptionMapper;
import sonia.scm.repository.NamespaceAndName;
import sonia.scm.repository.Permission;
import sonia.scm.repository.PermissionType;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryManager;
import sonia.scm.web.VndMediaType;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@Slf4j
@SubjectAware(
  username = "trillian",
  password = "secret",
  configuration = "classpath:sonia/scm/repository/shiro.ini"
)
public class PermissionRootResourceTest {
  private static final String REPOSITORY_NAMESPACE = "repo_namespace";
  private static final String REPOSITORY_NAME = "repo";
  private static final String PERMISSION_WRITE = "repository:permissionWrite:" + REPOSITORY_NAME;
  private static final String PERMISSION_READ = "repository:permissionRead:" + REPOSITORY_NAME;
  private static final String PERMISSION_OWNER = "repository:modify:" + REPOSITORY_NAME;

  private static final String PERMISSION_NAME = "perm";
  private static final String PATH_OF_ALL_PERMISSIONS = REPOSITORY_NAMESPACE + "/" + REPOSITORY_NAME + "/permissions/";
  private static final String PATH_OF_ONE_PERMISSION = PATH_OF_ALL_PERMISSIONS + PERMISSION_NAME;
  private static final String PERMISSION_TEST_PAYLOAD = "{ \"name\" : \"permission_name\", \"type\" : \"READ\"  }";
  private static final ArrayList<Permission> TEST_PERMISSIONS = Lists
    .newArrayList(
      new Permission("user_write", PermissionType.WRITE, false),
      new Permission("user_read", PermissionType.READ, false),
      new Permission("user_owner", PermissionType.OWNER, false),
      new Permission("group_read", PermissionType.READ, true),
      new Permission("group_write", PermissionType.WRITE, true),
      new Permission("group_owner", PermissionType.OWNER, true)
    );
  private final ExpectedRequest requestGETAllPermissions = new ExpectedRequest()
    .description("GET all permissions")
    .method("GET")
    .path(PATH_OF_ALL_PERMISSIONS);
  private final ExpectedRequest requestPOSTPermission = new ExpectedRequest()
    .description("create new permission")
    .method("POST")
    .content(PERMISSION_TEST_PAYLOAD)
    .path(PATH_OF_ALL_PERMISSIONS);
  private final ExpectedRequest requestGETPermission = new ExpectedRequest()
    .description("GET permission")
    .method("GET")
    .path(PATH_OF_ONE_PERMISSION);
  private final ExpectedRequest requestDELETEPermission = new ExpectedRequest()
    .description("delete permission")
    .method("DELETE")
    .path(PATH_OF_ONE_PERMISSION);
  private final ExpectedRequest requestPUTPermission = new ExpectedRequest()
    .description("update permission")
    .method("PUT")
    .content(PERMISSION_TEST_PAYLOAD)
    .path(PATH_OF_ONE_PERMISSION);

  private final Dispatcher dispatcher = MockDispatcherFactory.createDispatcher();

  @Rule
  public ShiroRule shiro = new ShiroRule();

  @Mock
  private RepositoryManager repositoryManager;

  private final URI baseUri = URI.create("/");
  private final ResourceLinks resourceLinks = ResourceLinksMock.createMock(baseUri);

  @InjectMocks
  private PermissionToPermissionDtoMapperImpl permissionToPermissionDtoMapper;

  @InjectMocks
  private PermissionDtoToPermissionMapperImpl permissionDtoToPermissionMapper;

  private PermissionCollectionToDtoMapper permissionCollectionToDtoMapper;

  private PermissionRootResource permissionRootResource;

  private final Subject subject = mock(Subject.class);
  private final ThreadState subjectThreadState = new SubjectThreadState(subject);

  @BeforeEach
  @Before
  public void prepareEnvironment() {
    initMocks(this);
    permissionCollectionToDtoMapper = new PermissionCollectionToDtoMapper(permissionToPermissionDtoMapper, resourceLinks);
    permissionRootResource = new PermissionRootResource(permissionDtoToPermissionMapper, permissionToPermissionDtoMapper, permissionCollectionToDtoMapper, resourceLinks, repositoryManager);
    RepositoryRootResource repositoryRootResource = new RepositoryRootResource(MockProvider
      .of(new RepositoryResource(null, null, null, null, null, null, null, null, MockProvider.of(permissionRootResource), null)), null);
    subjectThreadState.bind();
    ThreadContext.bind(subject);
    dispatcher.getRegistry().addSingletonResource(repositoryRootResource);
    dispatcher.getProviderFactory().registerProvider(RepositoryNotFoundExceptionMapper.class);
    dispatcher.getProviderFactory().registerProvider(PermissionNotFoundExceptionMapper.class);
    dispatcher.getProviderFactory().registerProvider(PermissionAlreadyExistsExceptionMapper.class);
    dispatcher.getProviderFactory().registerProvider(AuthorizationExceptionMapper.class);
  }

  @After
  public void unbind() {
    ThreadContext.unbindSubject();
  }

  @TestFactory
  @DisplayName("test endpoints on missing repository")
  Stream<DynamicTest> missedRepositoryTestFactory() {
    return createDynamicTestsToAssertResponses(
      requestGETAllPermissions.expectedResponseStatus(404),
      requestGETPermission.expectedResponseStatus(404),
      requestPOSTPermission.expectedResponseStatus(404),
      requestDELETEPermission.expectedResponseStatus(404),
      requestPUTPermission.expectedResponseStatus(404));
  }

  @TestFactory
  @DisplayName("test endpoints on missing permissions and user is Admin")
  Stream<DynamicTest> missedPermissionTestFactory() {
    Repository mockRepository = mock(Repository.class);
    when(mockRepository.getId()).thenReturn(REPOSITORY_NAME);
    when(mockRepository.getNamespace()).thenReturn(REPOSITORY_NAMESPACE);
    when(mockRepository.getName()).thenReturn(REPOSITORY_NAME);
    when(repositoryManager.get(any(NamespaceAndName.class))).thenReturn(mockRepository);
    return createDynamicTestsToAssertResponses(
      requestGETPermission.expectedResponseStatus(404),
      requestPOSTPermission.expectedResponseStatus(201),
      requestGETAllPermissions.expectedResponseStatus(200),
      requestDELETEPermission.expectedResponseStatus(204),
      requestPUTPermission.expectedResponseStatus(404));
  }

  @TestFactory
  @DisplayName("test endpoints on missing permissions and user is not Admin")
  Stream<DynamicTest> missedPermissionUserForbiddenTestFactory() {
    Repository mockRepository = mock(Repository.class);
    when(mockRepository.getId()).thenReturn(REPOSITORY_NAME);
    when(mockRepository.getNamespace()).thenReturn(REPOSITORY_NAMESPACE);
    when(mockRepository.getName()).thenReturn(REPOSITORY_NAME);
    doThrow(AuthorizationException.class).when(repositoryManager).get(any(NamespaceAndName.class));
    return createDynamicTestsToAssertResponses(
      requestGETPermission.expectedResponseStatus(403),
      requestPOSTPermission.expectedResponseStatus(403),
      requestGETAllPermissions.expectedResponseStatus(403),
      requestDELETEPermission.expectedResponseStatus(403),
      requestPUTPermission.expectedResponseStatus(403));
  }

  @Test
  public void userWithPermissionWritePermissionShouldGetAllPermissionsWithCreateAndUpdateLinks() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_WRITE);
    assertGettingExpectedPermissions(ImmutableList.copyOf(TEST_PERMISSIONS), PERMISSION_WRITE);
  }

  @Test
  public void userWithPermissionReadPermissionShouldGetAllPermissionsWithoutCreateAndUpdateLinks() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_READ);
    assertGettingExpectedPermissions(ImmutableList.copyOf(TEST_PERMISSIONS), PERMISSION_READ);
  }

  @Test
  public void shouldGetAllPermissions() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_READ);
    assertGettingExpectedPermissions(ImmutableList.copyOf(TEST_PERMISSIONS), PERMISSION_READ);
  }

  @Test
  public void shouldGetPermissionByName() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_READ);
    Permission expectedPermission = TEST_PERMISSIONS.get(0);
    assertExpectedRequest(requestGETPermission
      .expectedResponseStatus(200)
      .path(PATH_OF_ALL_PERMISSIONS + expectedPermission.getName())
      .responseValidator((response) -> {
        String body = response.getContentAsString();
        ObjectMapper mapper = new ObjectMapper();
        try {
          PermissionDto actualPermissionDto = mapper.readValue(body, PermissionDto.class);
          assertThat(actualPermissionDto)
            .as("response payload match permission object model")
            .isEqualToComparingFieldByFieldRecursively(getExpectedPermissionDto(expectedPermission, PERMISSION_READ))
          ;
        } catch (IOException e) {
          fail();
        }
      })
    );
  }

  @Test
  public void shouldGetCreatedPermissions() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_WRITE);
    Permission newPermission = new Permission("new_group_perm", PermissionType.WRITE, true);
    ArrayList<Permission> permissions = Lists.newArrayList(TEST_PERMISSIONS);
    permissions.add(newPermission);
    ImmutableList<Permission> expectedPermissions = ImmutableList.copyOf(permissions);
    assertExpectedRequest(requestPOSTPermission
      .content("{\"name\" : \"" + newPermission.getName() + "\" , \"type\" : \"WRITE\" , \"groupPermission\" : true}")
      .expectedResponseStatus(201)
      .responseValidator(response -> assertThat(response.getContentAsString())
        .as("POST response has no body")
        .isBlank())
    );
    assertGettingExpectedPermissions(expectedPermissions, PERMISSION_WRITE);
  }

  @Test
  public void shouldNotAddExistingPermission() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_WRITE);
    Permission newPermission = TEST_PERMISSIONS.get(0);
    assertExpectedRequest(requestPOSTPermission
      .content("{\"name\" : \"" + newPermission.getName() + "\" , \"type\" : \"WRITE\" , \"groupPermission\" : true}")
      .expectedResponseStatus(409)
    );
  }

  @Test
  public void shouldGetUpdatedPermissions() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_WRITE);
    Permission modifiedPermission = TEST_PERMISSIONS.get(0);
    // modify the type to owner
    modifiedPermission.setType(PermissionType.OWNER);
    ImmutableList<Permission> expectedPermissions = ImmutableList.copyOf(TEST_PERMISSIONS);
    assertExpectedRequest(requestPUTPermission
      .content("{\"name\" : \"" + modifiedPermission.getName() + "\" , \"type\" : \"OWNER\" , \"groupPermission\" : false}")
      .path(PATH_OF_ALL_PERMISSIONS + modifiedPermission.getName())
      .expectedResponseStatus(204)
      .responseValidator(response -> assertThat(response.getContentAsString())
        .as("PUT response has no body")
        .isBlank())
    );
    assertGettingExpectedPermissions(expectedPermissions, PERMISSION_WRITE);
  }


  @Test
  public void shouldDeletePermissions() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_OWNER);
    Permission deletedPermission = TEST_PERMISSIONS.get(0);
    ImmutableList<Permission> expectedPermissions = ImmutableList.copyOf(TEST_PERMISSIONS.subList(1, TEST_PERMISSIONS.size()));
    assertExpectedRequest(requestDELETEPermission
      .path(PATH_OF_ALL_PERMISSIONS + deletedPermission.getName())
      .expectedResponseStatus(204)
      .responseValidator(response -> assertThat(response.getContentAsString())
        .as("DELETE response has no body")
        .isBlank())
    );
    assertGettingExpectedPermissions(expectedPermissions, PERMISSION_READ);
  }

  @Test
  public void deletingNotExistingPermissionShouldProcess() throws URISyntaxException {
    createUserWithRepositoryAndPermissions(TEST_PERMISSIONS, PERMISSION_OWNER);
    Permission deletedPermission = TEST_PERMISSIONS.get(0);
    ImmutableList<Permission> expectedPermissions = ImmutableList.copyOf(TEST_PERMISSIONS.subList(1, TEST_PERMISSIONS.size()));
    assertExpectedRequest(requestDELETEPermission
      .path(PATH_OF_ALL_PERMISSIONS + deletedPermission.getName())
      .expectedResponseStatus(204)
      .responseValidator(response -> assertThat(response.getContentAsString())
        .as("DELETE response has no body")
        .isBlank())
    );
    assertGettingExpectedPermissions(expectedPermissions, PERMISSION_READ);
    assertExpectedRequest(requestDELETEPermission
      .path(PATH_OF_ALL_PERMISSIONS + deletedPermission.getName())
      .expectedResponseStatus(204)
      .responseValidator(response -> assertThat(response.getContentAsString())
        .as("DELETE response has no body")
        .isBlank())
    );
    assertGettingExpectedPermissions(expectedPermissions, PERMISSION_READ);
  }

  private void assertGettingExpectedPermissions(ImmutableList<Permission> expectedPermissions, String userPermission) throws URISyntaxException {
    assertExpectedRequest(requestGETAllPermissions
      .expectedResponseStatus(200)
      .responseValidator((response) -> {
        String body = response.getContentAsString();
        ObjectMapper mapper = new ObjectMapper();
        try {
          HalRepresentation halRepresentation = mapper.readValue(body, HalRepresentation.class);
          List<HalRepresentation> actualPermissionDtos = halRepresentation.getEmbedded().getItemsBy("permissions", HalRepresentation.class);
          List<PermissionDto> permissionDtoStream = actualPermissionDtos.stream()
            .map(hal -> {
              PermissionDto result = new PermissionDto();
              result.setName(hal.getAttribute("name").asText());
              result.setType(hal.getAttribute("type").asText());
              result.setGroupPermission(hal.getAttribute("groupPermission").asBoolean());
              result.add(hal.getLinks());
              return result;
            }).collect(Collectors.toList());
          assertThat(permissionDtoStream)
            .as("response payload match permission object models")
            .hasSize(expectedPermissions.size())
            .usingRecursiveFieldByFieldElementComparator()
            .containsExactlyInAnyOrder(getExpectedPermissionDtos(Lists.newArrayList(expectedPermissions), userPermission))
          ;
        } catch (IOException e) {
          fail();
        }
      })
    );
  }

  private PermissionDto[] getExpectedPermissionDtos(ArrayList<Permission> permissions, String userPermission) {
    return permissions
      .stream()
      .map(p -> getExpectedPermissionDto(p, userPermission))
      .toArray(PermissionDto[]::new);
  }

  private PermissionDto getExpectedPermissionDto(Permission permission, String userPermission) {
    PermissionDto result = new PermissionDto();
    result.setName(permission.getName());
    result.setGroupPermission(permission.isGroupPermission());
    result.setType(permission.getType().name());
    String permissionHref = "/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + PATH_OF_ALL_PERMISSIONS + permission.getName();
    if (PERMISSION_READ.equals(userPermission)) {
      result.add(linkingTo()
        .self(permissionHref)
        .build());
    } else {
      result.add(linkingTo()
        .self(permissionHref)
        .single(link("update", permissionHref))
        .single(link("delete", permissionHref))
        .build());
    }
    return result;
  }

  private Repository createUserWithRepository(String userPermission) {
    Repository mockRepository = mock(Repository.class);
    when(mockRepository.getId()).thenReturn(REPOSITORY_NAME);
    when(mockRepository.getNamespace()).thenReturn(REPOSITORY_NAMESPACE);
    when(mockRepository.getName()).thenReturn(REPOSITORY_NAME);
    when(repositoryManager.get(any(NamespaceAndName.class))).thenReturn(mockRepository);
    when(subject.isPermitted(userPermission != null ? eq(userPermission) : any(String.class))).thenReturn(true);
    return mockRepository;
  }

  private void createUserWithRepositoryAndPermissions(ArrayList<Permission> permissions, String userPermission) {
    when(createUserWithRepository(userPermission).getPermissions()).thenReturn(permissions);
  }

  private Stream<DynamicTest> createDynamicTestsToAssertResponses(ExpectedRequest... expectedRequests) {
    return Stream.of(expectedRequests)
      .map(entry -> dynamicTest("the endpoint " + entry.description + " should return the status code " + entry.expectedResponseStatus, () -> assertExpectedRequest(entry)));
  }

  private MockHttpResponse assertExpectedRequest(ExpectedRequest entry) throws URISyntaxException {
    MockHttpResponse response = new MockHttpResponse();
    HttpRequest request = null;
    request = MockHttpRequest
      .create(entry.method, "/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + entry.path)
      .content(entry.content)
      .contentType(VndMediaType.PERMISSION);
    dispatcher.invoke(request, response);
    log.info("Test the Request :{}", entry);
    assertThat(response.getStatus())
      .as("assert status code")
      .isEqualTo(entry.expectedResponseStatus);
    if (entry.responseValidator != null) {
      entry.responseValidator.accept(response);
    }
    return response;
  }

  @ToString
  public class ExpectedRequest {
    private String description;
    private String method;
    private String path;
    private int expectedResponseStatus;
    private byte[] content = new byte[]{};
    private Consumer<MockHttpResponse> responseValidator;

    public ExpectedRequest description(String description) {
      this.description = description;
      return this;
    }

    public ExpectedRequest method(String method) {
      this.method = method;
      return this;
    }

    public ExpectedRequest path(String path) {
      this.path = path;
      return this;
    }

    public ExpectedRequest content(String content) {
      if (content != null) {
        this.content = content.getBytes();
      }
      return this;
    }

    public ExpectedRequest expectedResponseStatus(int expectedResponseStatus) {
      this.expectedResponseStatus = expectedResponseStatus;
      return this;
    }

    public ExpectedRequest responseValidator(Consumer<MockHttpResponse> responseValidator) {
      this.responseValidator = responseValidator;
      return this;
    }
  }

}
