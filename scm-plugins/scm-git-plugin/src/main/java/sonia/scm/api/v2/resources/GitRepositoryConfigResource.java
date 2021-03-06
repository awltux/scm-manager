package sonia.scm.api.v2.resources;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.GitRepositoryConfig;
import sonia.scm.repository.NamespaceAndName;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryManager;
import sonia.scm.repository.RepositoryPermissions;
import sonia.scm.store.ConfigurationStore;
import sonia.scm.web.GitVndMediaType;
import sonia.scm.web.VndMediaType;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import static sonia.scm.ContextEntry.ContextBuilder.entity;
import static sonia.scm.NotFoundException.notFound;

public class GitRepositoryConfigResource {

  private static final Logger LOG = LoggerFactory.getLogger(GitRepositoryConfigResource.class);

  private final GitRepositoryConfigMapper repositoryConfigMapper;
  private final RepositoryManager repositoryManager;
  private final GitRepositoryConfigStoreProvider gitRepositoryConfigStoreProvider;

  @Inject
  public GitRepositoryConfigResource(GitRepositoryConfigMapper repositoryConfigMapper, RepositoryManager repositoryManager, GitRepositoryConfigStoreProvider gitRepositoryConfigStoreProvider) {
    this.repositoryConfigMapper = repositoryConfigMapper;
    this.repositoryManager = repositoryManager;
    this.gitRepositoryConfigStoreProvider = gitRepositoryConfigStoreProvider;
  }

  @GET
  @Path("/")
  @Produces(GitVndMediaType.GIT_REPOSITORY_CONFIG)
  @Operation(summary = "Git repository configuration", description = "Returns the repository related git configuration.", tags = "Git")
  @ApiResponse(
    responseCode = "200",
    description = "success",
    content = @Content(
      mediaType = GitVndMediaType.GIT_REPOSITORY_CONFIG,
      schema = @Schema(implementation = GitRepositoryConfigDto.class)
    )
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to read the repository config")
  @ApiResponse(
    responseCode = "404",
    description = "not found, no repository with the specified namespace and name available",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  public Response getRepositoryConfig(@PathParam("namespace") String namespace, @PathParam("name") String name) {
    Repository repository = getRepository(namespace, name);
    RepositoryPermissions.read(repository).check();
    ConfigurationStore<GitRepositoryConfig> repositoryConfigStore = getStore(repository);
    GitRepositoryConfig config = repositoryConfigStore.get();
    GitRepositoryConfigDto dto = repositoryConfigMapper.map(config, repository);
    return Response.ok(dto).build();
  }

  @PUT
  @Path("/")
  @Consumes(GitVndMediaType.GIT_REPOSITORY_CONFIG)
  @Operation(summary = "Modifies git repository configuration", description = "Modifies the repository related git configuration.", tags = "Git")
  @ApiResponse(
    responseCode = "204",
    description = "update success"
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user does not have the privilege to change this repositories config")
  @ApiResponse(
    responseCode = "404",
    description = "not found, no repository with the specified namespace and name available/name available",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  public Response setRepositoryConfig(@PathParam("namespace") String namespace, @PathParam("name") String name, GitRepositoryConfigDto dto) {
    Repository repository = getRepository(namespace, name);
    RepositoryPermissions.custom("git", repository).check();
    ConfigurationStore<GitRepositoryConfig> repositoryConfigStore = getStore(repository);
    GitRepositoryConfig config = repositoryConfigMapper.map(dto);
    repositoryConfigStore.set(config);
    LOG.info("git default branch of repository {} has changed, sending clear cache event", repository.getNamespaceAndName());
    return Response.noContent().build();
  }

  private Repository getRepository(@PathParam("namespace") String namespace, @PathParam("name") String name) {
    NamespaceAndName namespaceAndName = new NamespaceAndName(namespace, name);
    Repository repository = repositoryManager.get(namespaceAndName);
    if (repository == null) {
      throw notFound(entity(namespaceAndName));
    }
    return repository;
  }

  private ConfigurationStore<GitRepositoryConfig> getStore(Repository repository) {
    return gitRepositoryConfigStoreProvider.get(repository);
  }
}
