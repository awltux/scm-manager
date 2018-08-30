package sonia.scm.api.v2.resources;

import com.fasterxml.jackson.annotation.JsonInclude;
import de.otto.edison.hal.HalRepresentation;
import de.otto.edison.hal.Links;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.Pattern;
import java.time.Instant;
import java.util.Map;

@NoArgsConstructor @Getter @Setter
public class UserDto extends HalRepresentation {
  private boolean active;
  private boolean admin;
  private Instant creationDate;
  @NotEmpty
  private String displayName;
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private Instant lastModified;
  @NotEmpty
  @Email
  private String mail;
  @Pattern(regexp = "^[A-z0-9\\.\\-_@]|[^ ]([A-z0-9\\.\\-_@ ]*[A-z0-9\\.\\-_@]|[^ ])?$")
  private String name;
  private String password;
  private String type;
  private Map<String, String> properties;

  @Override
  @SuppressWarnings("squid:S1185") // We want to have this method available in this package
  protected HalRepresentation add(Links links) {
    return super.add(links);
  }
}
