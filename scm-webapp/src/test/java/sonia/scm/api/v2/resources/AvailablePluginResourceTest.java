package sonia.scm.api.v2.resources;

import de.otto.edison.hal.HalRepresentation;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.MockDispatcherFactory;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.jboss.resteasy.spi.UnhandledException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.plugin.PluginInformation;
import sonia.scm.plugin.PluginManager;
import sonia.scm.plugin.PluginState;
import sonia.scm.web.VndMediaType;

import javax.inject.Provider;
import javax.servlet.http.HttpServletResponse;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AvailablePluginResourceTest {

  private Dispatcher dispatcher;

  @Mock
  Provider<InstalledPluginResource> installedPluginResourceProvider;

  @Mock
  Provider<AvailablePluginResource> availablePluginResourceProvider;

  @Mock
  private PluginDtoCollectionMapper collectionMapper;

  @Mock
  private PluginManager pluginManager;

  @Mock
  private PluginDtoMapper mapper;

  @InjectMocks
  AvailablePluginResource availablePluginResource;

  PluginRootResource pluginRootResource;

  private final Subject subject = mock(Subject.class);


  @BeforeEach
  void prepareEnvironment() {
    dispatcher = MockDispatcherFactory.createDispatcher();
    pluginRootResource = new PluginRootResource(installedPluginResourceProvider, availablePluginResourceProvider);
    when(availablePluginResourceProvider.get()).thenReturn(availablePluginResource);
    dispatcher.getRegistry().addSingletonResource(pluginRootResource);
  }

  @Nested
  class withAuthorization {

    @BeforeEach
    void bindSubject() {
      ThreadContext.bind(subject);
      when(subject.isPermitted(any(String.class))).thenReturn(true);
    }

    @AfterEach
    public void unbindSubject() {
      ThreadContext.unbindSubject();
    }

    @Test
    void getAvailablePlugins() throws URISyntaxException, UnsupportedEncodingException {
      PluginInformation pluginInformation = new PluginInformation();
      pluginInformation.setState(PluginState.AVAILABLE);
      when(pluginManager.getAvailable()).thenReturn(Collections.singletonList(pluginInformation));
      when(collectionMapper.map(Collections.singletonList(pluginInformation))).thenReturn(new MockedResultDto());

      MockHttpRequest request = MockHttpRequest.get("/v2/plugins/available");
      request.accept(VndMediaType.PLUGIN_COLLECTION);
      MockHttpResponse response = new MockHttpResponse();

      dispatcher.invoke(request, response);

      assertThat(HttpServletResponse.SC_OK).isEqualTo(response.getStatus());
      assertThat(response.getContentAsString()).contains("\"marker\":\"x\"");
    }

    @Test
    void getAvailablePlugin() throws UnsupportedEncodingException, URISyntaxException {
      PluginInformation pluginInformation = new PluginInformation();
      pluginInformation.setState(PluginState.AVAILABLE);
      pluginInformation.setName("pluginName");
      pluginInformation.setVersion("2.0.0");
      when(pluginManager.getAvailable()).thenReturn(Collections.singletonList(pluginInformation));

      PluginDto pluginDto = new PluginDto();
      pluginDto.setName("pluginName");
      when(mapper.map(pluginInformation)).thenReturn(pluginDto);

      MockHttpRequest request = MockHttpRequest.get("/v2/plugins/available/pluginName/2.0.0");
      request.accept(VndMediaType.PLUGIN);
      MockHttpResponse response = new MockHttpResponse();

      dispatcher.invoke(request, response);

      assertThat(HttpServletResponse.SC_OK).isEqualTo(response.getStatus());
      assertThat(response.getContentAsString()).contains("\"name\":\"pluginName\"");
    }

    @Test
    void installPlugin() throws URISyntaxException {
      MockHttpRequest request = MockHttpRequest.post("/v2/plugins/available/pluginName/2.0.0/install");
      request.accept(VndMediaType.PLUGIN);
      MockHttpResponse response = new MockHttpResponse();

      dispatcher.invoke(request, response);

      verify(pluginManager).install("pluginName:2.0.0");
      assertThat(HttpServletResponse.SC_OK).isEqualTo(response.getStatus());
    }
  }

  @Nested
  class WithoutAuthorization {

    @BeforeEach
    void unbindSubject() {
      ThreadContext.unbindSubject();
    }

    @Test
    void shouldNotGetAvailablePluginsIfMissingPermission() throws URISyntaxException {
      MockHttpRequest request = MockHttpRequest.get("/v2/plugins/available");
      request.accept(VndMediaType.PLUGIN_COLLECTION);
      MockHttpResponse response = new MockHttpResponse();

      assertThrows(UnhandledException.class, () -> dispatcher.invoke(request, response));
    }

    @Test
    void shouldNotGetAvailablePluginIfMissingPermission() throws URISyntaxException {
      MockHttpRequest request = MockHttpRequest.get("/v2/plugins/available/pluginName/2.0.0");
      request.accept(VndMediaType.PLUGIN);
      MockHttpResponse response = new MockHttpResponse();

      assertThrows(UnhandledException.class, () -> dispatcher.invoke(request, response));
    }

    @Test
    void shouldNotInstallPluginIfMissingPermission() throws URISyntaxException {
      ThreadContext.unbindSubject();
      MockHttpRequest request = MockHttpRequest.post("/v2/plugins/available/pluginName/2.0.0/install");
      request.accept(VndMediaType.PLUGIN);
      MockHttpResponse response = new MockHttpResponse();

      assertThrows(UnhandledException.class, () -> dispatcher.invoke(request, response));
    }
  }

  public class MockedResultDto extends HalRepresentation {
    public String getMarker() {
      return "x";
    }
  }
}
