package sonia.scm.api.v2.resources;

import de.otto.edison.hal.Embedded;
import de.otto.edison.hal.Links;
import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Qualifier;
import sonia.scm.repository.BrowserResult;
import sonia.scm.repository.FileObject;
import sonia.scm.repository.Repository;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.Instant;
import java.util.Optional;
import java.util.OptionalLong;

@Mapper
public abstract class BrowserResultToFileObjectDtoMapper extends BaseFileObjectDtoMapper {

  FileObjectDto map(BrowserResult browserResult, @Context Repository repository) {
    FileObjectDto fileObjectDto = fileObjectToDto(browserResult.getFile(), repository, browserResult);
    fileObjectDto.setRevision(browserResult.getRevision());
    return fileObjectDto;
  }

  @Mapping(target = "attributes", ignore = true) // We do not map HAL attributes
  @Mapping(target = "children", qualifiedBy = Children.class)
  @Children
  protected abstract FileObjectDto fileObjectToDto(FileObject fileObject, @Context Repository repository, @Context BrowserResult browserResult);

  @Override
  void applyEnrichers(Links.Builder links, Embedded.Builder embeddedBuilder, Repository repository, BrowserResult browserResult, FileObject fileObject) {
    EdisonHalAppender appender = new EdisonHalAppender(links, embeddedBuilder);
    // we call enrichers, which are only responsible for top level browseresults
    applyEnrichers(appender, browserResult, repository, repository.getNamespaceAndName());
    // we call enrichers, which are responsible for all file object top level browse result and its children
    applyEnrichers(appender, fileObject, repository, repository.getNamespaceAndName(), browserResult, browserResult.getRevision());
  }

  Optional<Instant> mapOptionalInstant(OptionalLong optionalLong) {
    if (optionalLong.isPresent()) {
      return Optional.of(Instant.ofEpochMilli(optionalLong.getAsLong()));
    } else {
      return Optional.empty();
    }
  }

  @Qualifier
  @Target(ElementType.METHOD)
  @Retention(RetentionPolicy.CLASS)
  @interface Children {
  }
}
