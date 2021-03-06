package sonia.scm.api.v2.resources;

import org.mapstruct.*;
import sonia.scm.repository.Repository;

@Mapper
public abstract class RepositoryDtoToRepositoryMapper extends BaseDtoMapper {

  @Mapping(target = "creationDate", ignore = true)
  @Mapping(target = "id", ignore = true)
  @Mapping(target = "healthCheckFailures", ignore = true)
  public abstract Repository map(RepositoryDto repositoryDto, @Context String id);

  @AfterMapping
  void updateId(@MappingTarget Repository repository, @Context String id) {
    repository.setId(id);
  }
}
