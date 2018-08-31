package sonia.scm.api.v2.resources;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.MockDispatcherFactory;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import sonia.scm.repository.BrowserResult;
import sonia.scm.repository.FileObject;
import sonia.scm.repository.NamespaceAndName;
import sonia.scm.repository.RepositoryNotFoundException;
import sonia.scm.repository.RevisionNotFoundException;
import sonia.scm.repository.api.BrowseCommandBuilder;
import sonia.scm.repository.api.RepositoryService;
import sonia.scm.repository.api.RepositoryServiceFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;


@RunWith(MockitoJUnitRunner.Silent.class)
public class SourceRootResourceTest {

  private final Dispatcher dispatcher = MockDispatcherFactory.createDispatcher();
  private final URI baseUri = URI.create("/");
  private final ResourceLinks resourceLinks = ResourceLinksMock.createMock(baseUri);

  @Mock
  private RepositoryServiceFactory serviceFactory;
  @Mock
  private RepositoryService service;
  @Mock
  private BrowseCommandBuilder browseCommandBuilder;

  @Mock
  private FileObjectToFileObjectDtoMapper fileObjectToFileObjectDtoMapper;

  @InjectMocks
  private BrowserResultToBrowserResultDtoMapper browserResultToBrowserResultDtoMapper;


  @Before
  public void prepareEnvironment() throws Exception {
    when(serviceFactory.create(new NamespaceAndName("space", "repo"))).thenReturn(service);
    when(service.getBrowseCommand()).thenReturn(browseCommandBuilder);

    FileObjectDto dto = new FileObjectDto();
    dto.setName("name");
    dto.setLength(1024);

    when(fileObjectToFileObjectDtoMapper.map(any(FileObject.class), any(NamespaceAndName.class), anyString())).thenReturn(dto);
    SourceRootResource sourceRootResource = new SourceRootResource(serviceFactory, browserResultToBrowserResultDtoMapper);
    RepositoryRootResource repositoryRootResource =
      new RepositoryRootResource(MockProvider.of(new RepositoryResource(null,
        null,
        null,
        null,
        null,
        null,
        MockProvider.of(sourceRootResource),
        null,
        null)),
        null);

    dispatcher.getRegistry().addSingletonResource(repositoryRootResource);
  }

  @Test
  public void shouldReturnSources() throws URISyntaxException, IOException, RevisionNotFoundException {
    BrowserResult result = createBrowserResult();
    when(browseCommandBuilder.getBrowserResult()).thenReturn(result);
    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo/sources");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).contains("\"revision\":\"revision\"");
    assertThat(response.getContentAsString()).contains("\"tag\":\"tag\"");
    assertThat(response.getContentAsString()).contains("\"branch\":\"branch\"");
    assertThat(response.getContentAsString()).contains("\"files\":");
  }

  @Test
  public void shouldReturn404IfRepoNotFound() throws URISyntaxException, RepositoryNotFoundException {
    when(serviceFactory.create(new NamespaceAndName("idont", "exist"))).thenThrow(RepositoryNotFoundException.class);
    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "idont/exist/sources");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(404);
  }

  @Test
  public void shouldGetResultForSingleFile() throws URISyntaxException, IOException, RevisionNotFoundException {
    BrowserResult browserResult = new BrowserResult();
    browserResult.setBranch("abc");
    browserResult.setRevision("revision");
    browserResult.setTag("tag");
    browserResult.setPath("fileabc");
    FileObject fileObject = new FileObject();
    fileObject.setName("File Object!");

    browserResult.setFiles(Arrays.asList(fileObject));

    when(browseCommandBuilder.getBrowserResult()).thenReturn(browserResult);
    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo/sources/revision/fileabc");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).contains("\"revision\":\"revision\"");
    assertThat(response.getContentAsString()).contains("\"href\":\"/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "space/repo/sources/revision/fileabc\"");
  }

  @Test
  public void shouldGet404ForSingleFileIfRepoNotFound() throws URISyntaxException, RepositoryNotFoundException {
    when(serviceFactory.create(new NamespaceAndName("idont", "exist"))).thenThrow(RepositoryNotFoundException.class);

    MockHttpRequest request = MockHttpRequest.get("/" + RepositoryRootResource.REPOSITORIES_PATH_V2 + "idont/exist/sources/revision/fileabc");
    MockHttpResponse response = new MockHttpResponse();

    dispatcher.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(404);
  }

  private BrowserResult createBrowserResult() {
    return new BrowserResult("revision", "tag", "branch", createFileObjects(), "fileabc");
  }

  private List<FileObject> createFileObjects() {
    FileObject fileObject1 = new FileObject();
    fileObject1.setName("FO 1");
    fileObject1.setDirectory(false);
    fileObject1.setDescription("File object 1");
    fileObject1.setPath("/foo/bar/fo1");
    fileObject1.setLength(1024L);
    fileObject1.setLastModified(0L);

    FileObject fileObject2 = new FileObject();
    fileObject2.setName("FO 2");
    fileObject2.setDirectory(true);
    fileObject2.setDescription("File object 2");
    fileObject2.setPath("/foo/bar/fo2");
    fileObject2.setLength(4096L);
    fileObject2.setLastModified(1234L);

    return Arrays.asList(fileObject1, fileObject2);
  }
}
