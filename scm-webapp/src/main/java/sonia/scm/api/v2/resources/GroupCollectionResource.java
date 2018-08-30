package sonia.scm.api.v2.resources;

import com.webcohesion.enunciate.metadata.rs.ResponseCode;
import com.webcohesion.enunciate.metadata.rs.ResponseHeader;
import com.webcohesion.enunciate.metadata.rs.ResponseHeaders;
import com.webcohesion.enunciate.metadata.rs.StatusCodes;
import com.webcohesion.enunciate.metadata.rs.TypeHint;
import sonia.scm.AlreadyExistsException;
import sonia.scm.group.Group;
import sonia.scm.group.GroupManager;
import sonia.scm.web.VndMediaType;

import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;


public class GroupCollectionResource {
  
  private static final int DEFAULT_PAGE_SIZE = 10;
  private final GroupDtoToGroupMapper dtoToGroupMapper;
  private final GroupCollectionToDtoMapper groupCollectionToDtoMapper;
  private final ResourceLinks resourceLinks;

  private final IdResourceManagerAdapter<Group, GroupDto> adapter;

  @Inject
  public GroupCollectionResource(GroupManager manager, GroupDtoToGroupMapper dtoToGroupMapper, GroupCollectionToDtoMapper groupCollectionToDtoMapper, ResourceLinks resourceLinks) {
    this.dtoToGroupMapper = dtoToGroupMapper;
    this.groupCollectionToDtoMapper = groupCollectionToDtoMapper;
    this.resourceLinks = resourceLinks;
    this.adapter = new IdResourceManagerAdapter<>(manager, Group.class);
  }

  /**
   * Returns all groups for a given page number with a given page size (default page size is {@value DEFAULT_PAGE_SIZE}).
   *
   * <strong>Note:</strong> This method requires "group" privilege.
   *
   * @param page     the number of the requested page
   * @param pageSize the page size (default page size is {@value DEFAULT_PAGE_SIZE})
   * @param sortBy   sort parameter (if empty - undefined sorting)
   * @param desc     sort direction desc or aesc
   */
  @GET
  @Path("")
  @Produces(VndMediaType.GROUP_COLLECTION)
  @TypeHint(CollectionDto.class)
  @StatusCodes({
    @ResponseCode(code = 200, condition = "success"),
    @ResponseCode(code = 400, condition = "\"sortBy\" field unknown"),
    @ResponseCode(code = 401, condition = "not authenticated / invalid credentials"),
    @ResponseCode(code = 403, condition = "not authorized, the current user does not have the \"group\" privilege"),
    @ResponseCode(code = 500, condition = "internal server error")
  })
  public Response getAll(@DefaultValue("0") @QueryParam("page") int page,
    @DefaultValue("" + DEFAULT_PAGE_SIZE) @QueryParam("pageSize") int pageSize,
    @QueryParam("sortBy") String sortBy,
    @DefaultValue("false")
    @QueryParam("desc") boolean desc) {
    return adapter.getAll(page, pageSize, sortBy, desc,
                          pageResult -> groupCollectionToDtoMapper.map(page, pageSize, pageResult));
  }

  /**
   * Creates a new group.
   * @param groupDto The group to be created.
   * @return A response with the link to the new group (if created successfully).
   */
  @POST
  @Path("")
  @Consumes(VndMediaType.GROUP)
  @StatusCodes({
    @ResponseCode(code = 201, condition = "create success"),
    @ResponseCode(code = 401, condition = "not authenticated / invalid credentials"),
    @ResponseCode(code = 403, condition = "not authorized, the current user does not have the \"group\" privilege"),
    @ResponseCode(code = 409, condition = "conflict, a group with this name already exists"),
    @ResponseCode(code = 500, condition = "internal server error")
  })
  @TypeHint(TypeHint.NO_CONTENT.class)
  @ResponseHeaders(@ResponseHeader(name = "Location", description = "uri to the created group"))
  public Response create(@Valid GroupDto groupDto) throws AlreadyExistsException {
    return adapter.create(groupDto,
                          () -> dtoToGroupMapper.map(groupDto),
                          group -> resourceLinks.group().self(group.getName()));
  }
}
