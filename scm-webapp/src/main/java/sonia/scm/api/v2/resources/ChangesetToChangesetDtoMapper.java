package sonia.scm.api.v2.resources;

import de.otto.edison.hal.Links;
import org.mapstruct.AfterMapping;
import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import sonia.scm.repository.Branch;
import sonia.scm.repository.Changeset;
import sonia.scm.repository.Repository;
import sonia.scm.repository.Tag;
import sonia.scm.repository.api.Command;
import sonia.scm.repository.api.RepositoryService;
import sonia.scm.repository.api.RepositoryServiceFactory;

import javax.inject.Inject;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;

@Mapper
public abstract class ChangesetToChangesetDtoMapper extends BaseMapper<Changeset, ChangesetDto> {

  @Inject
  private RepositoryServiceFactory serviceFactory;

  @Inject
  private ResourceLinks resourceLinks;


  @Inject
  private BranchCollectionToDtoMapper branchCollectionToDtoMapper;

  @Inject
  private ChangesetToParentDtoMapper changesetToParentDtoMapper;

  @Inject
  private TagCollectionToDtoMapper tagCollectionToDtoMapper;


  @Mapping(target = "attributes", ignore = true) // We do not map HAL attributes
  public abstract ChangesetDto map(Changeset changeset, @Context Repository repository);


  @AfterMapping
  void appendLinks(Changeset source, @MappingTarget ChangesetDto target, @Context Repository repository) {
    String namespace = repository.getNamespace();
    String name = repository.getName();

    try (RepositoryService repositoryService = serviceFactory.create(repository)) {
      if (repositoryService.isSupported(Command.TAGS)) {
        target.withEmbedded("tags", tagCollectionToDtoMapper.getTagDtoList(namespace, name,
          getListOfObjects(source.getTags(), tagName -> new Tag(tagName, source.getId()))));
      }
      if (repositoryService.isSupported(Command.BRANCHES)) {
        target.withEmbedded("branches", branchCollectionToDtoMapper.getBranchDtoList(namespace, name,
          getListOfObjects(source.getBranches(), branchName -> new Branch(branchName, source.getId()))));
      }
    }
    target.withEmbedded("parents", getListOfObjects(source.getParents(), parent -> changesetToParentDtoMapper.map(new Changeset(parent, 0L, null), repository)));

    Links.Builder linksBuilder = linkingTo()
      .self(resourceLinks.changeset().self(repository.getNamespace(), repository.getName(), target.getId()))
      .single(link("diff", resourceLinks.diff().self(namespace, name, target.getId())));
    target.add(linksBuilder.build());
  }

  private <T> List<T> getListOfObjects(List<String> list, Function<String, T> mapFunction) {
    return list
      .stream()
      .map(mapFunction)
      .collect(Collectors.toList());
  }
}
