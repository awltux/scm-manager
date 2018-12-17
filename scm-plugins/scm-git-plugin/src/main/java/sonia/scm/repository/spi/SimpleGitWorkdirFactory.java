package sonia.scm.repository.spi;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.ScmTransportProtocol;
import org.eclipse.jgit.util.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.GitWorkdirFactory;
import sonia.scm.repository.InternalRepositoryException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class SimpleGitWorkdirFactory implements GitWorkdirFactory {

  private static final Logger logger = LoggerFactory.getLogger(SimpleGitWorkdirFactory.class);

  private final File poolDirectory;

  public SimpleGitWorkdirFactory() {
    this(new File(System.getProperty("java.io.tmpdir"), "scmm-git-pool"));
  }

  public SimpleGitWorkdirFactory(File poolDirectory) {
    this.poolDirectory = poolDirectory;
    poolDirectory.mkdirs();
  }

  public WorkingCopy createWorkingCopy(GitContext gitContext) {
    try {
      Repository clone = cloneRepository(gitContext.getDirectory(), createNewWorkdir());
      return new WorkingCopy(clone, this::close);
    } catch (GitAPIException e) {
      throw new InternalRepositoryException(gitContext.getRepository(), "could not clone working copy of repository", e);
    } catch (IOException e) {
      throw new InternalRepositoryException(gitContext.getRepository(), "could not create temporary directory for clone of repository", e);
    }
  }

  private File createNewWorkdir() throws IOException {
    return Files.createTempDirectory(poolDirectory.toPath(),"workdir").toFile();
  }

  protected Repository cloneRepository(File bareRepository, File target) throws GitAPIException {
    return Git.cloneRepository()
      .setURI(createScmTransportProtocolUri(bareRepository))
      .setDirectory(target)
      .call()
      .getRepository();
  }

  private String createScmTransportProtocolUri(File bareRepository) {
    return ScmTransportProtocol.NAME + "://" + bareRepository.getAbsolutePath();
  }

  private void close(Repository repository) {
    repository.close();
    try {
      FileUtils.delete(repository.getWorkTree(), FileUtils.RECURSIVE);
    } catch (IOException e) {
      logger.warn("could not delete temporary git workdir '{}'", repository.getWorkTree(), e);
    }
  }
}
