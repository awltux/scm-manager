package sonia.scm.web.lfs.servlet;

import com.google.common.annotations.VisibleForTesting;
import org.eclipse.jgit.lfs.server.LargeFileRepository;
import org.eclipse.jgit.lfs.server.LfsProtocolServlet;
import org.eclipse.jgit.lfs.server.fs.FileLfsServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.Repository;
import sonia.scm.store.BlobStore;
import sonia.scm.util.HttpUtil;
import sonia.scm.web.lfs.LfsAccessTokenFactory;
import sonia.scm.web.lfs.LfsBlobStoreFactory;
import sonia.scm.web.lfs.ScmBlobLfsRepository;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

/**
 * This factory class is a helper class to provide the {@link LfsProtocolServlet} and the {@link FileLfsServlet}
 * belonging to a SCM Repository.
 *
 * @since 1.54
 * Created by omilke on 11.05.2017.
 */
@Singleton
public class LfsServletFactory {

  private static final Logger LOG = LoggerFactory.getLogger(LfsServletFactory.class);

  private final LfsBlobStoreFactory lfsBlobStoreFactory;
  private final LfsAccessTokenFactory tokenFactory;

  @Inject
  public LfsServletFactory(LfsBlobStoreFactory lfsBlobStoreFactory, LfsAccessTokenFactory tokenFactory) {
    this.lfsBlobStoreFactory = lfsBlobStoreFactory;
    this.tokenFactory = tokenFactory;
  }

  /**
   * Builds the {@link LfsProtocolServlet} (jgit API) for a SCM Repository.
   *
   * @param repository The SCM Repository to build the servlet for.
   * @param request    The {@link HttpServletRequest} the used to access the SCM Repository.
   * @return The {@link LfsProtocolServlet} to provide the LFS Batch API for a SCM Repository.
   */
  public LfsProtocolServlet createProtocolServletFor(Repository repository, HttpServletRequest request) {
    LOG.trace("create lfs protocol servlet for repository {}", repository.getNamespaceAndName());
    BlobStore blobStore = lfsBlobStoreFactory.getLfsBlobStore(repository);
    String baseUri = buildBaseUri(repository, request);

    LargeFileRepository largeFileRepository = new ScmBlobLfsRepository(repository, blobStore, tokenFactory, baseUri);
    return new ScmLfsProtocolServlet(largeFileRepository);
  }

  /**
   * Builds the {@link FileLfsServlet} (jgit API) for a SCM Repository.
   *
   * @param repository The SCM Repository to build the servlet for.
   * @param request    The {@link HttpServletRequest} the used to access the SCM Repository.
   * @return The {@link FileLfsServlet} to provide the LFS Upload / Download API for a SCM Repository.
   */
  public HttpServlet createFileLfsServletFor(Repository repository, HttpServletRequest request) {
    LOG.trace("create lfs file servlet for repository {}", repository.getNamespaceAndName());
    return new ScmFileTransferServlet(lfsBlobStoreFactory.getLfsBlobStore(repository));
  }

  /**
   * Build the complete URI, under which the File Transfer API for this repository will be will be reachable.
   *
   * @param repository The repository to build the File Transfer URI for.
   * @param request    The request to construct the complete URI from.
   */
  @VisibleForTesting
  static String buildBaseUri(Repository repository, HttpServletRequest request) {
    return String.format("%s/repo/%s/%s.git/info/lfs/objects/", HttpUtil.getCompleteUrl(request), repository.getNamespace(), repository.getName());
  }

}
