package sonia.scm.api.v2.resources;

import com.google.inject.Inject;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import sonia.scm.config.ConfigurationPermissions;
import sonia.scm.repository.HgConfig;
import sonia.scm.repository.HgRepositoryHandler;
import sonia.scm.web.HgVndMediaType;
import sonia.scm.web.VndMediaType;

import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

public class HgConfigAutoConfigurationResource {

  private final HgRepositoryHandler repositoryHandler;
  private final HgConfigDtoToHgConfigMapper dtoToConfigMapper;

  @Inject
  public HgConfigAutoConfigurationResource(HgConfigDtoToHgConfigMapper dtoToConfigMapper,
                                           HgRepositoryHandler repositoryHandler) {
    this.dtoToConfigMapper = dtoToConfigMapper;
    this.repositoryHandler = repositoryHandler;
  }

  /**
   * Sets the default hg config and installs the hg binary.
   */
  @PUT
  @Path("")
  @Operation(summary = "Sets hg configuration and installs hg binary", description = "Sets the default mercurial config and installs the mercurial binary.", tags = "Mercurial")
  @ApiResponse(
    responseCode = "204",
    description = "update success"
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user does not have the \"configuration:write:hg\" privilege")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  public Response autoConfiguration() {
    return autoConfiguration(null);
  }

  /**
   * Modifies the hg config and installs the hg binary.
   *
   * @param configDto new configuration object
   */
  @PUT
  @Path("")
  @Consumes(HgVndMediaType.CONFIG)
  @Operation(summary = "Modifies hg configuration and installs hg binary", description = "Modifies the mercurial config and installs the mercurial binary.", tags = "Mercurial")
  @ApiResponse(
    responseCode = "204",
    description = "update success"
  )
  @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
  @ApiResponse(responseCode = "403", description = "not authorized, the current user does not have the \"configuration:write:hg\" privilege")
  @ApiResponse(
    responseCode = "500",
    description = "internal server error",
    content = @Content(
      mediaType = VndMediaType.ERROR_TYPE,
      schema = @Schema(implementation = ErrorDto.class)
    ))
  public Response autoConfiguration(HgConfigDto configDto) {

    HgConfig config;

    if (configDto != null) {
      config = dtoToConfigMapper.map(configDto);
    } else {
      config = new HgConfig();
    }

    ConfigurationPermissions.write(config).check();

    repositoryHandler.doAutoConfiguration(config);

    return Response.noContent().build();
  }
}
