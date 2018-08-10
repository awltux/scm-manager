package sonia.scm.api.v2.resources;

import org.mapstruct.Mapper;
import sonia.scm.repository.FileObject;

@Mapper
public abstract class FileObjectToFileObjectDtoMapper extends BaseMapper<FileObject, FileObjectDto> {

}