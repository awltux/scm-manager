package sonia.scm.repository.spi;

import com.google.common.util.concurrent.Striped;
import org.apache.commons.lang.StringUtils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.attributes.FilterCommandRegistry;
import org.eclipse.jgit.revwalk.RevCommit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.BadRequestException;
import sonia.scm.ConcurrentModificationException;
import sonia.scm.ContextEntry;
import sonia.scm.repository.GitWorkdirFactory;
import sonia.scm.repository.InternalRepositoryException;
import sonia.scm.repository.Repository;
import sonia.scm.web.lfs.LfsBlobStoreFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.locks.Lock;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static sonia.scm.AlreadyExistsException.alreadyExists;
import static sonia.scm.ContextEntry.ContextBuilder.entity;
import static sonia.scm.NotFoundException.notFound;

public class GitModifyCommand extends AbstractGitCommand implements ModifyCommand {

  private static final Logger LOG = LoggerFactory.getLogger(GitModifyCommand.class);
  private static final Striped<Lock> REGISTER_LOCKS = Striped.lock(5);

  private final GitWorkdirFactory workdirFactory;
  private final LfsBlobStoreFactory lfsBlobStoreFactory;

  GitModifyCommand(GitContext context, Repository repository, GitWorkdirFactory workdirFactory, LfsBlobStoreFactory lfsBlobStoreFactory) {
    super(context, repository);
    this.workdirFactory = workdirFactory;
    this.lfsBlobStoreFactory = lfsBlobStoreFactory;
  }

  @Override
  public String execute(ModifyCommandRequest request) {
    return inClone(clone -> new ModifyWorker(clone, request), workdirFactory, request.getBranch());
  }

  private class ModifyWorker extends GitCloneWorker<String> implements Worker {

    private final File workDir;
    private final ModifyCommandRequest request;

    ModifyWorker(Git clone, ModifyCommandRequest request) {
      super(clone);
      this.workDir = clone.getRepository().getWorkTree();
      this.request = request;
    }

    @Override
    String run() throws IOException {
      getClone().getRepository().getFullBranch();
      System.out.println("ls clone dir:");
      Arrays.stream(getClone().getRepository().getWorkTree().list()).forEach(System.out::println);
      if (!StringUtils.isEmpty(request.getExpectedRevision())) {
        if (!request.getExpectedRevision().equals(getCurrentRevision().getName())) {
          throw new ConcurrentModificationException("branch", request.getBranch() == null? "default": request.getBranch());
        }
      }
      for (ModifyCommandRequest.PartialRequest r : request.getRequests()) {
        r.execute(this);
      }
      failIfNotChanged(NoChangesMadeException::new);
      Optional<RevCommit> revCommit = doCommit(request.getCommitMessage(), request.getAuthor());
      push();
      return revCommit.orElseThrow(NoChangesMadeException::new).name();
    }

    @Override
    public void create(String toBeCreated, File file, boolean overwrite) throws IOException {
      Path targetFile = new File(workDir, toBeCreated).toPath();
      createDirectories(targetFile);
      if (overwrite) {
        Files.move(file.toPath(), targetFile, REPLACE_EXISTING);
      } else {
        try {
          Files.move(file.toPath(), targetFile);
        } catch (FileAlreadyExistsException e) {
          throw alreadyExists(createFileContext(toBeCreated));
        }
      }

      addToGitWithLfsSupport(toBeCreated, targetFile);
    }

    @Override
    public void modify(String path, File file) throws IOException {
      Path targetFile = new File(workDir, path).toPath();
      createDirectories(targetFile);
      if (!targetFile.toFile().exists()) {
        throw notFound(createFileContext(path));
      }
      Files.move(file.toPath(), targetFile, REPLACE_EXISTING);

      addToGitWithLfsSupport(path, targetFile);
    }

    private void addToGitWithLfsSupport(String path, Path targetFile) {
      REGISTER_LOCKS.get(targetFile).lock();
      try {
        LfsBlobStoreCleanFilterFactory cleanFilterFactory = new LfsBlobStoreCleanFilterFactory(lfsBlobStoreFactory, repository, targetFile);

        String registerKey = "git-lfs clean -- '" + path + "'";
        LOG.info("register lfs filter command factory for command '{}'", registerKey);
        FilterCommandRegistry.register(registerKey, cleanFilterFactory::createFilter);
        try {
          addFileToGit(path);
        } catch (GitAPIException e) {
          throwInternalRepositoryException("could not add file to index", e);
        } finally {
          LOG.info("unregister lfs filter command factory for command \"{}\"", registerKey);
          FilterCommandRegistry.unregister(registerKey);
        }
      } finally {
        REGISTER_LOCKS.get(targetFile).unlock();
      }
    }

    private void addFileToGit(String toBeCreated) throws GitAPIException {
      getClone().add().addFilepattern(removeStartingPathSeparators(toBeCreated)).call();
    }

    @Override
    public void delete(String toBeDeleted) throws IOException {
      Path fileToBeDeleted = new File(workDir, toBeDeleted).toPath();
      try {
        Files.delete(fileToBeDeleted);
      } catch (NoSuchFileException e) {
        throw notFound(createFileContext(toBeDeleted));
      }
      try {
        getClone().rm().addFilepattern(removeStartingPathSeparators(toBeDeleted)).call();
      } catch (GitAPIException e) {
        throwInternalRepositoryException("could not remove file from index", e);
      }
    }

    private String removeStartingPathSeparators(String path) {
      while (path.startsWith(File.separator)) {
        path = path.substring(1);
      }
      return path;
    }

    private void createDirectories(Path targetFile) throws IOException {
      try {
        Files.createDirectories(targetFile.getParent());
      } catch (FileAlreadyExistsException e) {
        throw alreadyExists(createFileContext(targetFile.toString()));
      }
    }

    private ContextEntry.ContextBuilder createFileContext(String path) {
      ContextEntry.ContextBuilder contextBuilder = entity("file", path);
      if (!StringUtils.isEmpty(request.getBranch())) {
        contextBuilder.in("branch", request.getBranch());
      }
      contextBuilder.in(context.getRepository());
      return contextBuilder;
    }

    @Override
    public void move(String sourcePath, String targetPath) {

    }

    private class NoChangesMadeException extends BadRequestException {
      public NoChangesMadeException() {
        super(ContextEntry.ContextBuilder.entity(context.getRepository()).build(), "no changes detected to branch " + ModifyWorker.this.request.getBranch());
      }

      @Override
      public String getCode() {
        return "40RaYIeeR1";
      }
    }
  }

  private String throwInternalRepositoryException(String message, Exception e) {
    throw new InternalRepositoryException(context.getRepository(), message, e);
  }
}
