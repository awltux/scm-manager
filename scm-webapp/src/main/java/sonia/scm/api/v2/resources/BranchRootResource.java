package sonia.scm.api.v2.resources;

import com.google.common.base.Strings;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import sonia.scm.PageResult;
import sonia.scm.repository.Branch;
import sonia.scm.repository.Branches;
import sonia.scm.repository.Changeset;
import sonia.scm.repository.ChangesetPagingResult;
import sonia.scm.repository.NamespaceAndName;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryPermissions;
import sonia.scm.repository.api.BranchCommandBuilder;
import sonia.scm.repository.api.CommandNotSupportedException;
import sonia.scm.repository.api.RepositoryService;
import sonia.scm.repository.api.RepositoryServiceFactory;
import sonia.scm.web.VndMediaType;

import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;

import static sonia.scm.AlreadyExistsException.alreadyExists;
import static sonia.scm.ContextEntry.ContextBuilder.entity;
import static sonia.scm.NotFoundException.notFound;

public class BranchRootResource {

  private final RepositoryServiceFactory serviceFactory;
  private final BranchToBranchDtoMapper branchToDtoMapper;
  private final BranchCollectionToDtoMapper branchCollectionToDtoMapper;

  private final BranchChangesetCollectionToDtoMapper branchChangesetCollectionToDtoMapper;

  private final ResourceLinks resourceLinks;

  @Inject
  public BranchRootResource(RepositoryServiceFactory serviceFactory, BranchToBranchDtoMapper branchToDtoMapper, BranchCollectionToDtoMapper branchCollectionToDtoMapper, BranchChangesetCollectionToDtoMapper changesetCollectionToDtoMapper, ResourceLinks resourceLinks) {
    this.serviceFactory = serviceFactory;
    this.branchToDtoMapper = branchToDtoMapper;
    this.branchCollectionToDtoMapper = branchCollectionToDtoMapper;
    this.branchChangesetCollectionToDtoMapper = changesetCollectionToDtoMapper;
    this.resourceLinks = resourceLinks;
  }

  /**
   * Returns a branch for a repository.
   *
   * <strong>Note:</strong> This method requires "repository" privilege.
   *
   * @param namespace  the namespace of the repository
   * @param name       the name of the repository
   * @param branchName the name of the branch
   */
  @GET
  @Path("{branch}")
  @Produces(VndMediaType.BRANCH)
  @Operation(summary = "Get single branch", description = "Returns a branch for a repository.", tags = "Repository")
  @ApiResponse(
    responseCode = "200",
    description = "success",
    content = @Content(
      mediaType = VndMediaType.BRANCH,
      schema = @Schema(implementation = BranchDto.class)
    )
  )
  @ApiResponse(responseCode = "400", description = "branches not supported for given repository")
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to read the branch")
  @ApiResponse(
    responseCode = "404",
    description = "not found, no branch with the specified name for the repository available or repository found",
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
    )
  )
  public Response get(@PathParam("namespace") String namespace, @PathParam("name") String name, @PathParam("branch") String branchName) throws IOException {
    NamespaceAndName namespaceAndName = new NamespaceAndName(namespace, name);
    try (RepositoryService repositoryService = serviceFactory.create(namespaceAndName)) {
      Branches branches = repositoryService.getBranchesCommand().getBranches();
      return branches.getBranches()
        .stream()
        .filter(branch -> branchName.equals(branch.getName()))
        .findFirst()
        .map(branch -> branchToDtoMapper.map(branch, namespaceAndName))
        .map(Response::ok)
        .orElseThrow(() -> notFound(entity("branch", branchName).in(namespaceAndName)))
        .build();
    } catch (CommandNotSupportedException ex) {
      return Response.status(Response.Status.BAD_REQUEST).build();
    }
  }

  @GET
  @Path("{branch}/changesets/")
  @Produces(VndMediaType.CHANGESET_COLLECTION)
  @Operation(summary = "Collection of changesets", description = "Returns a collection of changesets for specific branch.", tags = "Repository")
  @ApiResponse(
    responseCode = "200",
    description = "success",
    content = @Content(
      mediaType = VndMediaType.CHANGESET_COLLECTION,
      schema = @Schema(implementation = CollectionDto.class)
    )
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user has no privileges to read the changeset")
  @ApiResponse(
    responseCode = "404",
    description = "not found, no changesets available in the repository",
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
    )
  )
  public Response history(@PathParam("namespace") String namespace,
                          @PathParam("name") String name,
                          @PathParam("branch") String branchName,
                          @DefaultValue("0") @QueryParam("page") int page,
                          @DefaultValue("10") @QueryParam("pageSize") int pageSize) throws IOException {
    try (RepositoryService repositoryService = serviceFactory.create(new NamespaceAndName(namespace, name))) {
      if (!branchExists(branchName, repositoryService)) {
        throw notFound(entity(Branch.class, branchName).in(Repository.class, namespace + "/" + name));
      }
      Repository repository = repositoryService.getRepository();
      RepositoryPermissions.read(repository).check();
      ChangesetPagingResult changesets = new PagedLogCommandBuilder(repositoryService)
        .page(page)
        .pageSize(pageSize)
        .create()
        .setBranch(branchName)
        .getChangesets();
      if (changesets != null && changesets.getChangesets() != null) {
        PageResult<Changeset> pageResult = new PageResult<>(changesets.getChangesets(), changesets.getTotal());
        return Response.ok(branchChangesetCollectionToDtoMapper.map(page, pageSize, pageResult, repository, branchName)).build();
      } else {
        return Response.ok().build();
      }
    }
  }

  /**
   * Creates a new branch.
   *
   * @param namespace     the namespace of the repository
   * @param name          the name of the repository
   * @param branchRequest the request giving the name of the new branch and an optional parent branch
   * @return A response with the link to the new branch (if created successfully).
   */
  @POST
  @Path("")
  @Consumes(VndMediaType.BRANCH_REQUEST)
  @Operation(summary = "Create branch", description = "Creates a new branch.", tags = "Repository")
  @ApiResponse(
    responseCode = "201",
    description = "create success",
    headers = @Header(
      name = "Location",
      description = "uri to the created branch",
      schema = @Schema(type = "string")
    )
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user does not have the \"push\" privilege")
  @ApiResponse(responseCode = "409", description = "conflict, a branch with this name already exists")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  public Response create(@PathParam("namespace") String namespace,
                         @PathParam("name") String name,
                         @Valid BranchRequestDto branchRequest) throws IOException {
    NamespaceAndName namespaceAndName = new NamespaceAndName(namespace, name);
    String branchName = branchRequest.getName();
    String parentName = branchRequest.getParent();
    try (RepositoryService repositoryService = serviceFactory.create(namespaceAndName)) {
      if (branchExists(branchName, repositoryService)) {
        throw alreadyExists(entity(Branch.class, branchName).in(Repository.class, namespace + "/" + name));
      }
      Repository repository = repositoryService.getRepository();
      RepositoryPermissions.push(repository).check();
      BranchCommandBuilder branchCommand = repositoryService.getBranchCommand();
      if (!Strings.isNullOrEmpty(parentName)) {
        if (!branchExists(parentName, repositoryService)) {
          throw notFound(entity(Branch.class, parentName).in(Repository.class, namespace + "/" + name));
        }
        branchCommand.from(parentName);
      }
      Branch newBranch = branchCommand.branch(branchName);
      return Response.created(URI.create(resourceLinks.branch().self(namespaceAndName, newBranch.getName()))).build();
    }
  }

  private boolean branchExists(String branchName, RepositoryService repositoryService) throws IOException {
    return repositoryService.getBranchesCommand()
      .getBranches()
      .getBranches()
      .stream()
      .anyMatch(branch -> branchName.equals(branch.getName()));
  }

  /**
   * Returns the branches for a repository.
   *
   * <strong>Note:</strong> This method requires "repository" privilege.
   *
   * @param namespace the namespace of the repository
   * @param name      the name of the repository
   */
  @GET
  @Path("")
  @Produces(VndMediaType.BRANCH_COLLECTION)
  @Operation(summary = "List of branches", description = "Returns all branches for a repository.", tags = "Repository")
  @ApiResponse(
    responseCode = "200",
    description = "success",
    content = @Content(
      mediaType = VndMediaType.BRANCH_COLLECTION,
      schema = @Schema(implementation = CollectionDto.class)
    )
  )
  @ApiResponse(responseCode = "400", description = "branches not supported for given repository")
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user does not have the \"read repository\" privilege")
  @ApiResponse(
    responseCode = "404",
    description = "not found, no repository found for the given namespace and name",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    )
  )
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  public Response getAll(@PathParam("namespace") String namespace, @PathParam("name") String name) throws IOException {
    try (RepositoryService repositoryService = serviceFactory.create(new NamespaceAndName(namespace, name))) {
      Branches branches = repositoryService.getBranchesCommand().getBranches();
      return Response.ok(branchCollectionToDtoMapper.map(repositoryService.getRepository(), branches.getBranches())).build();
    } catch (CommandNotSupportedException ex) {
      return Response.status(Response.Status.BAD_REQUEST).build();
    }
  }
}
