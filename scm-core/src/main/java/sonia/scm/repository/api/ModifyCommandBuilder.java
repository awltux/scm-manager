package sonia.scm.repository.api;

import com.google.common.base.Preconditions;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.io.Files;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.Person;
import sonia.scm.repository.spi.ModifyCommand;
import sonia.scm.repository.spi.ModifyCommandRequest;
import sonia.scm.repository.util.WorkdirProvider;
import sonia.scm.util.IOUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Use this {@link ModifyCommandBuilder} to make file changes to the head of a branch. You can
 * <ul>
 *   <li>create new files ({@link #createFile(String)} (with the option to overwrite a file, if it already exists; by
 *   default a {@link sonia.scm.AlreadyExistsException} will be thrown)</li>
 *   <li>modify existing files ({@link #modifyFile(String)}</li>
 *   <li>delete existing files ({@link #deleteFile(String)}</li>
 *   <li>move/rename existing files ({@link #moveFile(String, String)}</li>
 * </ul>
 *
 * You can collect multiple changes before they are executed with a call to {@link #execute()}.
 *
 * <p>Example:
 * <pre>
 * commandBuilder
 *     .setBranch("feature/branch")
 *     .setCommitMessage("make some changes")
 *     .setAuthor(new Person())
 *     .createFile("file/to/create").withData(inputStream)
 *     .deleteFile("old/file/to/delete")
 *     .execute();
 * </pre>
 * </p>
 */
public class ModifyCommandBuilder implements AutoCloseable {

  private static final Logger LOG = LoggerFactory.getLogger(ModifyCommandBuilder.class);

  private final ModifyCommand command;
  private final File workdir;

  private final ModifyCommandRequest request = new ModifyCommandRequest();

  ModifyCommandBuilder(ModifyCommand command, WorkdirProvider workdirProvider) {
    this.command = command;
    this.workdir = workdirProvider.createNewWorkdir();
  }

  /**
   * Set the branch that should be modified. The new commit will be made for this branch.
   * @param branchToModify The branch to modify.
   * @return This builder instance.
   */
  public ModifyCommandBuilder setBranchToModify(String branchToModify) {
    return this;
  }

  /**
   * Create a new file. The content of the file will be specified in a subsequent call to
   * {@link ContentLoader#withData(ByteSource)} or {@link ContentLoader#withData(InputStream)}.
   * By default, an {@link sonia.scm.AlreadyExistsException} will be thrown, when there already
   * exists a file with the given path. You can disable this setting
   * {@link WithOverwriteFlagContentLoader#setOverwrite(boolean)} to <code>true</code>.
   * @param path The path and the name of the file that should be created.
   * @return The loader to specify the content of the new file.
   */
  public WithOverwriteFlagContentLoader createFile(String path) {
    return new WithOverwriteFlagContentLoader(
      (content, overwrite) -> request.addRequest(new ModifyCommandRequest.CreateFileRequest(path, content, overwrite))
    );
  }

  /**
   * Modify an existing file. The new content of the file will be specified in a subsequent call to
   * {@link ContentLoader#withData(ByteSource)} or {@link ContentLoader#withData(InputStream)}.
   * @param path The path and the name of the file that should be modified.
   * @return The loader to specify the new content of the file.
   */
  public SimpleContentLoader modifyFile(String path) {
    return new SimpleContentLoader(
      content -> request.addRequest(new ModifyCommandRequest.ModifyFileRequest(path, content))
    );
  }

  /**
   * Delete an existing file.
   * @param path The path and the name of the file that should be deleted.
   * @return This builder instance.
   */
  public ModifyCommandBuilder deleteFile(String path) {
    request.addRequest(new ModifyCommandRequest.DeleteFileRequest(path));
    return this;
  }

  /**
   * Move an existing file.
   * @param sourcePath The path and the name of the file that should be moved.
   * @param targetPath The new path and name the file should be moved to.
   * @return This builder instance.
   */
  public ModifyCommandBuilder moveFile(String sourcePath, String targetPath) {
    request.addRequest(new ModifyCommandRequest.MoveFileRequest(sourcePath, targetPath));
    return this;
  }

  /**
   * Apply the changes and create a new commit with the given message and author.
   * @return The revision of the new commit.
   */
  public String execute() {
    Preconditions.checkArgument(request.isValid(), "commit message, branch and at least one request are required");
    return command.execute(request);
  }

  /**
   * Set the commit message for the new commit.
   * @return This builder instance.
   */
  public ModifyCommandBuilder setCommitMessage(String message) {
    request.setCommitMessage(message);
    return this;
  }

  /**
   * Set the author for the new commit.
   * @return This builder instance.
   */
  public ModifyCommandBuilder setAuthor(Person author) {
    request.setAuthor(author);
    return this;
  }

  /**
   * Set the branch the changes should be made upon.
   * @return This builder instance.
   */
  public ModifyCommandBuilder setBranch(String branch) {
    request.setBranch(branch);
    return this;
  }

  @Override
  public void close() {
    try {
      IOUtil.delete(workdir);
    } catch (IOException e) {
      LOG.warn("could not delete temporary workdir '{}'", workdir, e);
    }
  }

  public interface ContentLoader {
    /**
     * Specify the data of the file using a {@link ByteSource}.
     *
     * @return The builder instance.
     * @throws IOException If the data could not be read.
     */
    ModifyCommandBuilder withData(ByteSource data) throws IOException;

    /**
     * Specify the data of the file using an {@link InputStream}.
     * @return The builder instance.
     * @throws IOException If the data could not be read.
     */
    ModifyCommandBuilder withData(InputStream data) throws IOException;
  }

  public class SimpleContentLoader implements ContentLoader {

    private final Consumer<File> contentConsumer;

    private SimpleContentLoader(Consumer<File> contentConsumer) {
      this.contentConsumer = contentConsumer;
    }

    @Override
    public ModifyCommandBuilder withData(ByteSource data) throws IOException {
      File content = loadData(data);
      contentConsumer.accept(content);
      return ModifyCommandBuilder.this;
    }

    @Override
    public ModifyCommandBuilder withData(InputStream data) throws IOException {
      File content = loadData(data);
      contentConsumer.accept(content);
      return ModifyCommandBuilder.this;
    }
  }

  public class WithOverwriteFlagContentLoader implements ContentLoader {

    private final ContentLoader contentLoader;
    private boolean overwrite = false;

    private WithOverwriteFlagContentLoader(BiConsumer<File, Boolean> contentConsumer) {
      this.contentLoader = new SimpleContentLoader(file -> contentConsumer.accept(file, overwrite));
    }

    /**
     * Set this to <code>true</code> to overwrite the file if it already exists. Otherwise an
     * {@link sonia.scm.AlreadyExistsException} will be thrown.
     * @return This loader instance.
     */
    public WithOverwriteFlagContentLoader setOverwrite(boolean overwrite) {
      this.overwrite = overwrite;
      return this;
    }

    @Override
    public ModifyCommandBuilder withData(ByteSource data) throws IOException {
      return contentLoader.withData(data);
    }

    @Override
    public ModifyCommandBuilder withData(InputStream data) throws IOException {
      return contentLoader.withData(data);
    }
  }

  @SuppressWarnings("UnstableApiUsage") // Files only used internal
  private File loadData(ByteSource data) throws IOException {
    File file = createTemporaryFile();
    data.copyTo(Files.asByteSink(file));
    return file;
  }

  @SuppressWarnings("UnstableApiUsage") // Files and ByteStreams only used internal
  private File loadData(InputStream data) throws IOException {
    File file = createTemporaryFile();
    try (OutputStream out = Files.asByteSink(file).openBufferedStream()) {
      ByteStreams.copy(data, out);
    }
    return file;
  }

  private File createTemporaryFile() throws IOException {
    return File.createTempFile("upload-", "", workdir);
  }
}
