package sonia.scm.api.v2.resources;

import com.github.sdorra.shiro.ShiroRule;
import com.github.sdorra.shiro.SubjectAware;
import com.google.common.io.Resources;
import com.google.inject.util.Providers;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import sonia.scm.PageResult;
import sonia.scm.repository.NamespaceAndName;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryIsNotArchivedException;
import sonia.scm.repository.RepositoryManager;
import sonia.scm.repository.api.RepositoryService;
import sonia.scm.repository.api.RepositoryServiceFactory;
import sonia.scm.user.User;
import sonia.scm.web.VndMediaType;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import static java.util.Collections.singletonList;
import static java.util.stream.Stream.of;
import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static javax.servlet.http.HttpServletResponse.SC_NO_CONTENT;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_PRECONDITION_FAILED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static sonia.scm.api.v2.resources.DispatcherMock.createDispatcher;

@SubjectAware(
  username = "trillian",
  password = "secret",
  configuration = "classpath:sonia/scm/repository/shiro.ini"
)
public class RepositoryRootResourceTest extends RepositoryTestBase {

  private static final String REALM = "AdminRealm";

  private Dispatcher dispatcher;

  @Rule
  public ShiroRule shiro = new ShiroRule();

  @Mock
  private RepositoryManager repositoryManager;
  @Mock
  private RepositoryServiceFactory serviceFactory;
  @Mock
  private RepositoryService service;
  @Mock
  private ScmPathInfoStore scmPathInfoStore;
  @Mock
  private ScmPathInfo uriInfo;


  private final URI baseUri = URI.create("/");
  private final ResourceLinks resourceLinks = ResourceLinksMock.createMock(baseUri);

  @InjectMocks
  private RepositoryToRepositoryDtoMapperImpl repositoryToDtoMapper;
  @InjectMocks
  private RepositoryDtoToRepositoryMapperImpl dtoToRepositoryMapper;

  @Before
  public void prepareEnvironment() {
    initMocks(this);
    super.repositoryToDtoMapper = repositoryToDtoMapper;
    super.dtoToRepositoryMapper = dtoToRepositoryMapper;
    super.manager = repositoryManager;
    RepositoryCollectionToDtoMapper repositoryCollectionToDtoMapper = new RepositoryCollectionToDtoMapper(repositoryToDtoMapper, resourceLinks);
    super.repositoryCollectionResource = Providers.of(new RepositoryCollectionResource(repositoryManager, repositoryCollectionToDtoMapper, dtoToRepositoryMapper, resourceLinks));
    dispatcher = createDispatcher(getRepositoryRootResource());
    when(serviceFactory.create(any(Repository.class))).thenReturn(service);
    when(scmPathInfoStore.get()).thenReturn(uriInfo);
    when(uriInfo.getApiRestUri()).thenReturn(URI.create("/x/y"));
    SimplePrincipalCollection trillian = new SimplePrincipalCollection("trillian", REALM);
    trillian.add(new User("trillian"), REALM);
    shiro.setSubject(
      new Subject.Builder()
        .principals(trillian)
        .authenticated(true)
        .buildSubject());
  }

  @Test
  public void shouldFailForNotExistingRepository() throws URISyntaxException {
    when(repositoryManager.get(any(NamespaceAndName.class))).thenReturn(null);
    mockRepository("space", "repo");

    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/other");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_NOT_FOUND, response.getStatus());
  }

  @Test
  public void shouldFindExistingRepository() throws URISyntaxException {
    mockRepository("space", "repo");

    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_OK, response.getStatus());
    assertTrue(response.getContentAsString().contains("\"name\":\"repo\""));
  }

  @Test
  public void shouldMapProperties() throws URISyntaxException {
    Repository repository = mockRepository("space", "repo");
    repository.setProperty("testKey", "testValue");

    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertTrue(response.getContentAsString().contains("\"testKey\":\"testValue\""));
  }

  @Test
  public void shouldGetAll() throws URISyntaxException {
    PageResult<Repository> singletonPageResult = createSingletonPageResult(mockRepository("space", "repo"));
    when(repositoryManager.getPage(any(), eq(0), eq(10))).thenReturn(singletonPageResult);

    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2);
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_OK, response.getStatus());
    assertTrue(response.getContentAsString().contains("\"name\":\"repo\""));
  }

  @Test
  public void shouldHandleUpdateForNotExistingRepository() throws URISyntaxException, IOException {
    URL url = Resources.getResource("sonia/scm/api/v2/repository-test-update.json");
    byte[] repository = Resources.toByteArray(url);
    when(repositoryManager.get(any(NamespaceAndName.class))).thenReturn(null);

    MockHttpRequest request = MockHttpRequest
      .put("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo")
      .contentType(VndMediaType.REPOSITORY)
      .content(repository);
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_NOT_FOUND, response.getStatus());
  }

  @Test
  public void shouldHandleUpdateForExistingRepository() throws Exception {
    mockRepository("space", "repo");

    URL url = Resources.getResource("sonia/scm/api/v2/repository-test-update.json");
    byte[] repository = Resources.toByteArray(url);

    MockHttpRequest request = MockHttpRequest
      .put("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo")
      .contentType(VndMediaType.REPOSITORY)
      .content(repository);
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_NO_CONTENT, response.getStatus());
    verify(repositoryManager).modify(anyObject());
  }

  @Test
  public void shouldHandleUpdateForExistingRepositoryForChangedNamespace() throws Exception {
    mockRepository("wrong", "repo");

    URL url = Resources.getResource("sonia/scm/api/v2/repository-test-update.json");
    byte[] repository = Resources.toByteArray(url);

    MockHttpRequest request = MockHttpRequest
      .put("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "wrong/repo")
      .contentType(VndMediaType.REPOSITORY)
      .content(repository);
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_BAD_REQUEST, response.getStatus());
    verify(repositoryManager, never()).modify(anyObject());
  }

  @Test
  public void shouldHandleDeleteForExistingRepository() throws Exception {
    mockRepository("space", "repo");

    MockHttpRequest request = MockHttpRequest.delete("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_NO_CONTENT, response.getStatus());
    verify(repositoryManager).delete(anyObject());
  }

  @Test
  public void shouldHandleDeleteIsNotArchivedException() throws Exception {
    mockRepository("space", "repo");

    doThrow(RepositoryIsNotArchivedException.class).when(repositoryManager).delete(anyObject());

    MockHttpRequest request = MockHttpRequest.delete("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_PRECONDITION_FAILED, response.getStatus());
  }

  @Test
  public void shouldCreateNewRepositoryInCorrectNamespace() throws Exception {
    when(repositoryManager.create(any())).thenAnswer(invocation -> {
      Repository repository = (Repository) invocation.getArguments()[0];
      repository.setNamespace("otherspace");
      return repository;
    });

    URL url = Resources.getResource("sonia/scm/api/v2/repository-test-update.json");
    byte[] repositoryJson = Resources.toByteArray(url);

    MockHttpRequest request = MockHttpRequest
      .post("/" + RepositoryRootResource.REPOSITORIES_PATH_V2)
      .contentType(VndMediaType.REPOSITORY)
      .content(repositoryJson);
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(HttpServletResponse.SC_CREATED, response.getStatus());
    assertEquals("/v2/repositories/otherspace/repo", response.getOutputHeaders().get("Location").get(0).toString());
    verify(repositoryManager).create(any(Repository.class));
  }

  @Test
  public void shouldSetCurrentUserAsOwner() throws Exception {
    ArgumentCaptor<Repository> createCaptor = ArgumentCaptor.forClass(Repository.class);
    when(repositoryManager.create(createCaptor.capture())).thenAnswer(invocation -> {
      Repository repository = (Repository) invocation.getArguments()[0];
      repository.setNamespace("otherspace");
      return repository;
    });

    URL url = Resources.getResource("sonia/scm/api/v2/repository-test-update.json");
    byte[] repositoryJson = Resources.toByteArray(url);

    MockHttpRequest request = MockHttpRequest
      .post("/" + RepositoryRootResource.REPOSITORIES_PATH_V2)
      .contentType(VndMediaType.REPOSITORY)
      .content(repositoryJson);
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertThat(createCaptor.getValue().getPermissions())
      .hasSize(1)
      .allSatisfy(p -> {
        assertThat(p.getName()).isEqualTo("trillian");
        assertThat(p.getVerbs()).containsExactly("*");
      });
  }

  @Test
  public void shouldCreateArrayOfProtocolUrls() throws Exception {
    mockRepository("space", "repo");
    when(service.getSupportedProtocols()).thenReturn(of(new MockScmProtocol("http", "http://"), new MockScmProtocol("ssh", "ssh://")));

    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);

    assertEquals(SC_OK, response.getStatus());
    assertTrue(response.getContentAsString().contains("\"protocol\":[{\"href\":\"http://\",\"name\":\"http\"},{\"href\":\"ssh://\",\"name\":\"ssh\"}]"));
  }

  private PageResult<Repository> createSingletonPageResult(Repository repository) {
    return new PageResult<>(singletonList(repository), 0);
  }

  private Repository mockRepository(String namespace, String name) {
    Repository repository = new Repository();
    repository.setNamespace(namespace);
    repository.setName(name);
    String id = namespace + "-" + name;
    repository.setId(id);
    when(repositoryManager.get(new NamespaceAndName(namespace, name))).thenReturn(repository);
    when(repositoryManager.get(id)).thenReturn(repository);
    return repository;
  }
}
