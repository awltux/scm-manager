package sonia.scm.api.v2.resources;

import com.google.inject.Inject;
import de.otto.edison.hal.Links;
import org.mapstruct.AfterMapping;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;
import sonia.scm.repository.HealthCheckFailure;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryPermissions;
import sonia.scm.repository.api.Command;
import sonia.scm.repository.api.RepositoryService;
import sonia.scm.repository.api.RepositoryServiceFactory;

import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;

// Mapstruct does not support parameterized (i.e. non-default) constructors. Thus, we need to use field injection.
@SuppressWarnings("squid:S3306")
@Mapper
public abstract class RepositoryToRepositoryDtoMapper extends BaseMapper<Repository, RepositoryDto> {

  @Inject
  private ResourceLinks resourceLinks;
  @Inject
  private RepositoryServiceFactory serviceFactory;

  abstract HealthCheckFailureDto toDto(HealthCheckFailure failure);

  @AfterMapping
  void appendLinks(Repository repository, @MappingTarget RepositoryDto target) {
    Links.Builder linksBuilder = linkingTo().self(resourceLinks.repository().self(target.getNamespace(), target.getName()));
    linksBuilder.single(link("httpProtocol", resourceLinks.repository().clone(target.getType(), target.getNamespace(), target.getName())));
    if (RepositoryPermissions.delete(repository).isPermitted()) {
      linksBuilder.single(link("delete", resourceLinks.repository().delete(target.getNamespace(), target.getName())));
    }
    if (RepositoryPermissions.modify(repository).isPermitted()) {
      linksBuilder.single(link("update", resourceLinks.repository().update(target.getNamespace(), target.getName())));
      linksBuilder.single(link("permissions", resourceLinks.permission().all(target.getNamespace(), target.getName())));
    }
    try (RepositoryService repositoryService = serviceFactory.create(repository)) {
      if (repositoryService.isSupported(Command.TAGS)) {
        linksBuilder.single(link("tags", resourceLinks.tagCollection().self(target.getNamespace(), target.getName())));
      }
      if (repositoryService.isSupported(Command.BRANCHES)) {
        linksBuilder.single(link("branches", resourceLinks.branchCollection().self(target.getNamespace(), target.getName())));
      }
    }
    linksBuilder.single(link("changesets", resourceLinks.changeset().self(target.getNamespace(), target.getName())));
    linksBuilder.single(link("sources", resourceLinks.source().selfWithoutRevision(target.getNamespace(), target.getName(), "")));
    target.add(linksBuilder.build());
  }
}
