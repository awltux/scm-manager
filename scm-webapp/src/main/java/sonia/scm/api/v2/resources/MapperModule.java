package sonia.scm.api.v2.resources;

import com.google.inject.AbstractModule;
import com.google.inject.servlet.ServletScopes;
import org.mapstruct.factory.Mappers;

public class MapperModule extends AbstractModule {
  @Override
  protected void configure() {
    bind(UserDtoToUserMapper.class).to(Mappers.getMapper(UserDtoToUserMapper.class).getClass());
    bind(UserToUserDtoMapper.class).to(Mappers.getMapper(UserToUserDtoMapper.class).getClass());
    bind(UserCollectionToDtoMapper.class);

    bind(GroupDtoToGroupMapper.class).to(Mappers.getMapper(GroupDtoToGroupMapper.class).getClass());
    bind(GroupToGroupDtoMapper.class).to(Mappers.getMapper(GroupToGroupDtoMapper.class).getClass());
    bind(GroupCollectionToDtoMapper.class);

    bind(ScmConfigurationToConfigDtoMapper.class).to(Mappers.getMapper(ScmConfigurationToConfigDtoMapper.class).getClass());
    bind(ConfigDtoToScmConfigurationMapper.class).to(Mappers.getMapper(ConfigDtoToScmConfigurationMapper.class).getClass());

    bind(RepositoryToRepositoryDtoMapper.class).to(Mappers.getMapper(RepositoryToRepositoryDtoMapper.class).getClass());
    bind(RepositoryDtoToRepositoryMapper.class).to(Mappers.getMapper(RepositoryDtoToRepositoryMapper.class).getClass());

    bind(UriInfoStore.class).in(ServletScopes.REQUEST);
  }
}
