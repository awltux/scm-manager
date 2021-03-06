package sonia.scm.api.v2.resources;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.tags.Tag;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.ws.rs.Path;

/**
 * RESTful Web Service Resource to manage repositories.
 */
@OpenAPIDefinition(
  tags = {
    @Tag(name = "Repository", description = "Repository related endpoints")
  }
)
@Path(RepositoryRootResource.REPOSITORIES_PATH_V2)
public class RepositoryRootResource {
  static final String REPOSITORIES_PATH_V2 = "v2/repositories/";

  private final Provider<RepositoryResource> repositoryResource;
  private final Provider<RepositoryCollectionResource> repositoryCollectionResource;

  @Inject
  public RepositoryRootResource(Provider<RepositoryResource> repositoryResource, Provider<RepositoryCollectionResource> repositoryCollectionResource) {
    this.repositoryResource = repositoryResource;
    this.repositoryCollectionResource = repositoryCollectionResource;
  }

  @Path("{namespace}/{name}")
  public RepositoryResource getRepositoryResource() {
    return repositoryResource.get();
  }

  @Path("")
  public RepositoryCollectionResource getRepositoryCollectionResource() {
    return repositoryCollectionResource.get();
  }
}
