package sonia.scm.api.v2.resources;

import com.webcohesion.enunciate.metadata.rs.ResponseCode;
import com.webcohesion.enunciate.metadata.rs.StatusCodes;
import com.webcohesion.enunciate.metadata.rs.TypeHint;
import sonia.scm.repository.Branches;
import sonia.scm.repository.NamespaceAndName;
import sonia.scm.repository.RepositoryNotFoundException;
import sonia.scm.repository.api.CommandNotSupportedException;
import sonia.scm.repository.api.RepositoryService;
import sonia.scm.repository.api.RepositoryServiceFactory;
import sonia.scm.web.VndMediaType;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.io.IOException;

public class BranchRootResource {

  private final RepositoryServiceFactory servicefactory;
  private final BranchToBranchDtoMapper branchToDtoMapper;
  private final BranchCollectionToDtoMapper branchCollectionToDtoMapper;

  @Inject
  public BranchRootResource(RepositoryServiceFactory servicefactory, BranchToBranchDtoMapper branchToDtoMapper, BranchCollectionToDtoMapper branchCollectionToDtoMapper) {
    this.servicefactory = servicefactory;
    this.branchToDtoMapper = branchToDtoMapper;
    this.branchCollectionToDtoMapper = branchCollectionToDtoMapper;
  }

  /**
   * Returns a branch for a repository.
   *
   * <strong>Note:</strong> This method requires "repository" privilege.
   *
   * @param namespace the namespace of the repository
   * @param name the name of the repository
   * @param branchName the name of the branch
   *
   */
  @GET
  @Path("{branch}")
  @Produces(VndMediaType.BRANCH)
  @TypeHint(BranchDto.class)
  @StatusCodes({
    @ResponseCode(code = 200, condition = "success"),
    @ResponseCode(code = 400, condition = "branches not supported for given repository"),
    @ResponseCode(code = 401, condition = "not authenticated / invalid credentials"),
    @ResponseCode(code = 403, condition = "not authorized, the current user has no privileges to read the branch"),
    @ResponseCode(code = 404, condition = "not found, no branch with the specified name for the repository available or repository not found"),
    @ResponseCode(code = 500, condition = "internal server error")
  })
  public Response get(@PathParam("namespace") String namespace, @PathParam("name") String name, @PathParam("branch") String branchName) throws IOException {
    try (RepositoryService repositoryService = servicefactory.create(new NamespaceAndName(namespace, name))) {
      Branches branches = repositoryService.getBranchesCommand().getBranches();
      return branches.getBranches()
        .stream()
        .filter(branch -> branchName.equals(branch.getName()))
        .findFirst()
        .map(branch -> branchToDtoMapper.map(branch, new NamespaceAndName(namespace, name)))
        .map(Response::ok)
        .orElse(Response.status(Response.Status.NOT_FOUND))
        .build();
    } catch (CommandNotSupportedException ex) {
      return Response.status(Response.Status.BAD_REQUEST).build();
    } catch (RepositoryNotFoundException e) {
      return Response.status(Response.Status.NOT_FOUND).build();
    }
  }

  @Path("{branch}/changesets/")
  @GET
  public Response history(@PathParam("namespace") String namespace, @PathParam("name") String name, @PathParam("branch") String branchName) {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the branches for a repository.
   *
   * <strong>Note:</strong> This method requires "repository" privilege.
   *
   * @param namespace the namespace of the repository
   * @param name the name of the repository
   *
   */
  @GET
  @Path("")
  @Produces(VndMediaType.BRANCH_COLLECTION)
  @TypeHint(CollectionDto.class)
  @StatusCodes({
    @ResponseCode(code = 200, condition = "success"),
    @ResponseCode(code = 400, condition = "branches not supported for given repository"),
    @ResponseCode(code = 401, condition = "not authenticated / invalid credentials"),
    @ResponseCode(code = 403, condition = "not authorized, the current user does not have the \"group\" privilege"),
    @ResponseCode(code = 404, condition = "not found, no repository found for the given namespace and name"),
    @ResponseCode(code = 500, condition = "internal server error")
  })
  public Response getAll(@PathParam("namespace") String namespace, @PathParam("name") String name) throws IOException {
    try (RepositoryService repositoryService = servicefactory.create(new NamespaceAndName(namespace, name))) {
      Branches branches = repositoryService.getBranchesCommand().getBranches();
      return Response.ok(branchCollectionToDtoMapper.map(namespace, name, branches.getBranches())).build();
    } catch (CommandNotSupportedException ex) {
      return Response.status(Response.Status.BAD_REQUEST).build();
    } catch (RepositoryNotFoundException e) {
      return Response.status(Response.Status.NOT_FOUND).build();
    }
  }
}
