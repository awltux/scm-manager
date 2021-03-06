package sonia.scm.api.v2.resources;

import de.otto.edison.hal.Embedded;
import de.otto.edison.hal.HalRepresentation;
import de.otto.edison.hal.Links;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class TagDto extends HalRepresentation {

  private String name;

  private String revision;

  TagDto(Links links, Embedded embedded) {
    super(links, embedded);
  }

}
