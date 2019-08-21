package sonia.scm.api.v2.resources;

import com.google.inject.Inject;
import de.otto.edison.hal.Embedded;
import de.otto.edison.hal.HalRepresentation;
import de.otto.edison.hal.Links;
import sonia.scm.plugin.PluginInformation;
import sonia.scm.plugin.PluginWrapper;

import java.util.Collection;
import java.util.List;

import static de.otto.edison.hal.Embedded.embeddedBuilder;
import static de.otto.edison.hal.Links.linkingTo;
import static java.util.stream.Collectors.toList;

public class PluginDtoCollectionMapper {

  private final ResourceLinks resourceLinks;
  private final PluginDtoMapper mapper;

  @Inject
  public PluginDtoCollectionMapper(ResourceLinks resourceLinks, PluginDtoMapper mapper) {
    this.resourceLinks = resourceLinks;
    this.mapper = mapper;
  }

  public HalRepresentation map(List<PluginWrapper> plugins) {
    List<PluginDto> dtos = plugins.stream().map(mapper::map).collect(toList());
    return new HalRepresentation(createInstalledPluginsLinks(), embedDtos(dtos));
  }

  public HalRepresentation map(Collection<PluginInformation> plugins) {
    List<PluginDto> dtos = plugins.stream().map(mapper::map).collect(toList());
    return new HalRepresentation(createAvailablePluginsLinks(), embedDtos(dtos));
  }

  private Links createInstalledPluginsLinks() {
    String baseUrl = resourceLinks.installedPluginCollection().self();

    Links.Builder linksBuilder = linkingTo()
      .with(Links.linkingTo().self(baseUrl).build());
    return linksBuilder.build();
  }

  private Links createAvailablePluginsLinks() {
    String baseUrl = resourceLinks.availablePluginCollection().self();

    Links.Builder linksBuilder = linkingTo()
      .with(Links.linkingTo().self(baseUrl).build());
    return linksBuilder.build();
  }

  private Embedded embedDtos(List<PluginDto> dtos) {
    return embeddedBuilder()
      .with("plugins", dtos)
      .build();
  }
}
