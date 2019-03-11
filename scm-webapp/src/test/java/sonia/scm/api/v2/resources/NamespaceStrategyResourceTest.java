package sonia.scm.api.v2.resources;

import com.google.common.collect.Lists;
import com.google.inject.util.Providers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.repository.NamespaceStrategy;
import sonia.scm.repository.Repository;

import javax.inject.Provider;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NamespaceStrategyResourceTest {

  @Mock
  private UriInfo uriInfo;

  @Test
  void shouldReturnNamespaceStrategies() {
    when(uriInfo.getAbsolutePath()).thenReturn(URI.create("/namespace-strategies"));

    Set<NamespaceStrategy> namespaceStrategies = allStrategies();
    Provider<NamespaceStrategy> current = Providers.of(new MegaNamespaceStrategy());

    NamespaceStrategyResource resource = new NamespaceStrategyResource(namespaceStrategies, current);

    NamespaceStrategiesDto dto = resource.get(uriInfo);
    assertThat(dto.getCurrent()).isEqualTo(MegaNamespaceStrategy.class.getName());
    assertThat(dto.getAvailable()).contains(
      AwesomeNamespaceStrategy.class.getName(),
      SuperNamespaceStrategy.class.getName(),
      MegaNamespaceStrategy.class.getName()
    );
    assertThat(dto.getLinks().getLinkBy("self").get().getHref()).isEqualTo("/namespace-strategies");
  }

  private Set<NamespaceStrategy> allStrategies() {
    return  strategies(new AwesomeNamespaceStrategy(), new SuperNamespaceStrategy(), new MegaNamespaceStrategy());
  }

  private Set<NamespaceStrategy> strategies(NamespaceStrategy... strategies) {
    return new LinkedHashSet<>(Lists.newArrayList(strategies));
  }

  private static class AwesomeNamespaceStrategy implements NamespaceStrategy {
    @Override
    public String createNamespace(Repository repository) {
      return "awesome";
    }
  }

  private static class SuperNamespaceStrategy implements NamespaceStrategy {
    @Override
    public String createNamespace(Repository repository) {
      return "super";
    }
  }

  private static class MegaNamespaceStrategy implements NamespaceStrategy {
    @Override
    public String createNamespace(Repository repository) {
      return "mega";
    }
  }
}
