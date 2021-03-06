package sonia.scm.api.v2.resources;

import com.google.inject.Inject;
import de.otto.edison.hal.Embedded;
import de.otto.edison.hal.HalRepresentation;
import de.otto.edison.hal.Links;
import sonia.scm.plugin.AvailablePlugin;
import sonia.scm.plugin.InstalledPlugin;
import sonia.scm.plugin.PluginManager;

import java.util.List;

import static de.otto.edison.hal.Embedded.embeddedBuilder;
import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;
import static java.util.stream.Collectors.toList;

public class PluginDtoCollectionMapper {

  private final ResourceLinks resourceLinks;
  private final PluginDtoMapper mapper;
  private final PluginManager manager;

  @Inject
  public PluginDtoCollectionMapper(ResourceLinks resourceLinks, PluginDtoMapper mapper, PluginManager manager) {
    this.resourceLinks = resourceLinks;
    this.mapper = mapper;
    this.manager = manager;
  }

  public HalRepresentation mapInstalled(List<InstalledPlugin> plugins, List<AvailablePlugin> availablePlugins) {
    List<PluginDto> dtos = plugins
      .stream()
      .map(i -> mapper.mapInstalled(i, availablePlugins))
      .collect(toList());
    return new HalRepresentation(createInstalledPluginsLinks(), embedDtos(dtos));
  }

  public HalRepresentation mapAvailable(List<AvailablePlugin> plugins) {
    List<PluginDto> dtos = plugins.stream().map(mapper::mapAvailable).collect(toList());
    return new HalRepresentation(createAvailablePluginsLinks(plugins), embedDtos(dtos));
  }

  private Links createInstalledPluginsLinks() {
    String baseUrl = resourceLinks.installedPluginCollection().self();

    Links.Builder linksBuilder = linkingTo()
      .with(Links.linkingTo().self(baseUrl).build());

    if (!manager.getUpdatable().isEmpty()) {
      linksBuilder.single(link("update", resourceLinks.installedPluginCollection().update()));
    }

    return linksBuilder.build();
  }

  private Links createAvailablePluginsLinks(List<AvailablePlugin> plugins) {
    String baseUrl = resourceLinks.availablePluginCollection().self();

    Links.Builder linksBuilder = linkingTo()
      .with(Links.linkingTo().self(baseUrl).build());

    return linksBuilder.build();
  }

  private boolean containsPending(List<AvailablePlugin> plugins) {
    return plugins.stream().anyMatch(AvailablePlugin::isPending);
  }

  private Embedded embedDtos(List<PluginDto> dtos) {
    return embeddedBuilder()
      .with("plugins", dtos)
      .build();
  }
}
