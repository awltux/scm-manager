package sonia.scm.api.v2.resources;

import de.otto.edison.hal.Embedded;
import de.otto.edison.hal.HalRepresentation;
import de.otto.edison.hal.Links;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import javax.validation.constraints.NotEmpty;

import java.time.Instant;
import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
public class RepositoryRoleDto extends HalRepresentation {
  @NotEmpty
  private String name;
  @NoBlankStrings @NotEmpty
  private Collection<String> verbs;
  private String type;
  private Instant creationDate;
  private Instant lastModified;

  RepositoryRoleDto(Links links, Embedded embedded) {
    super(links, embedded);
  }
}
