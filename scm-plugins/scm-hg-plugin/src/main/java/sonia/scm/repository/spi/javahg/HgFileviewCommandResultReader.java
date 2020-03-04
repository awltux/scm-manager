package sonia.scm.repository.spi.javahg;

import com.aragost.javahg.DateTime;
import com.aragost.javahg.internals.HgInputStream;
import com.google.common.base.Strings;
import sonia.scm.repository.FileObject;
import sonia.scm.repository.SubRepository;

import java.io.IOException;
import java.util.Deque;
import java.util.LinkedList;

class HgFileviewCommandResultReader {

  private static final char TRUNCATED_MARK = 't';

  private final HgInputStream stream;
  private final boolean disableLastCommit;

  HgFileviewCommandResultReader(HgInputStream stream, boolean disableLastCommit) {
    this.stream = stream;
    this.disableLastCommit = disableLastCommit;
  }

  FileObject parseResult() throws IOException {
    Deque<FileObject> stack = new LinkedList<>();

    FileObject last = null;
    while (stream.peek() != -1 && stream.peek() != TRUNCATED_MARK) {
      FileObject file = read(stream);

      while (!stack.isEmpty()) {
        FileObject current = stack.peek();
        if (isParent(current, file)) {
          current.addChild(file);
          break;
        } else {
          stack.pop();
        }
      }

      if (file.isDirectory()) {
        stack.push(file);
      }
      last = file;
    }

    if (stack.isEmpty()) {
      // if the stack is empty, the requested path is probably a file
      return last;
    } else {
      // if the stack is not empty, the requested path is a directory
      if (stream.read() == TRUNCATED_MARK) {
        stack.getLast().setTruncated(true);
      }
      return stack.getLast();
    }
  }

  private FileObject read(HgInputStream stream) throws IOException {
    char type = (char) stream.read();

    FileObject file;
    switch (type) {
      case 'd':
        file = readDirectory(stream);
        break;
      case 'f':
        file = readFile(stream);
        break;
      case 's':
        file = readSubRepository(stream);
        break;
      default:
        throw new IOException("unknown file object type: " + type);
    }
    return file;
  }

  private boolean isParent(FileObject parent, FileObject child) {
    String parentPath = parent.getPath();
    if (parentPath.equals("")) {
      return true;
    }
    return child.getParentPath().equals(parentPath);
  }

  private FileObject readDirectory(HgInputStream stream) throws IOException {
    FileObject directory = new FileObject();
    String path = removeTrailingSlash(stream.textUpTo('\0'));

    directory.setName(getNameFromPath(path));
    directory.setDirectory(true);
    directory.setPath(path);

    return directory;
  }

  private FileObject readFile(HgInputStream stream) throws IOException {
    FileObject file = new FileObject();
    String path = removeTrailingSlash(stream.textUpTo('\n'));

    file.setName(getNameFromPath(path));
    file.setPath(path);
    file.setDirectory(false);
    file.setLength((long) stream.decimalIntUpTo(' '));

    DateTime timestamp = stream.dateTimeUpTo(' ');
    String description = stream.textUpTo('\0');

    if (!disableLastCommit) {
      file.setCommitDate(timestamp.getDate().getTime());
      file.setDescription(description);
    }

    return file;
  }

  private FileObject readSubRepository(HgInputStream stream) throws IOException {
    FileObject directory = new FileObject();
    String path = removeTrailingSlash(stream.textUpTo('\n'));

    directory.setName(getNameFromPath(path));
    directory.setDirectory(true);
    directory.setPath(path);

    String revision = stream.textUpTo(' ');
    String url = stream.textUpTo('\0');

    SubRepository subRepository = new SubRepository(url);

    if (!Strings.isNullOrEmpty(revision)) {
      subRepository.setRevision(revision);
    }

    directory.setSubRepository(subRepository);

    return directory;
  }

  private String removeTrailingSlash(String path) {
    if (path.endsWith("/")) {
      path = path.substring(0, path.length() - 1);
    }

    return path;
  }

  private String getNameFromPath(String path) {
    int index = path.lastIndexOf('/');

    if (index > 0) {
      path = path.substring(index + 1);
    }

    return path;
  }
}
