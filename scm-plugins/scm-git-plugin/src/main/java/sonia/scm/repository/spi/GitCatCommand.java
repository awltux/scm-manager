/**
 * Copyright (c) 2010, Sebastian Sdorra
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of SCM-Manager; nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * http://bitbucket.org/sdorra/scm-manager
 *
 */


package sonia.scm.repository.spi;

import org.eclipse.jgit.errors.MissingObjectException;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectLoader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevTree;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.eclipse.jgit.treewalk.filter.PathFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.GitUtil;
import sonia.scm.repository.PathNotFoundException;
import sonia.scm.repository.RevisionNotFoundException;
import sonia.scm.util.Util;

import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


public class GitCatCommand extends AbstractGitCommand implements CatCommand {

  private static final Logger logger = LoggerFactory.getLogger(GitCatCommand.class);

  public GitCatCommand(GitContext context, sonia.scm.repository.Repository repository) {
    super(context, repository);
  }

  @Override
  public void getCatResult(CatCommandRequest request, OutputStream output) throws IOException, PathNotFoundException, RevisionNotFoundException {
    logger.debug("try to read content for {}", request);
    try (ClosableObjectLoaderContainer closableObjectLoaderContainer = getLoader(request)) {
      closableObjectLoaderContainer.objectLoader.copyTo(output);
    }
  }

  @Override
  public InputStream getCatResultStream(CatCommandRequest request) throws IOException, PathNotFoundException, RevisionNotFoundException {
    logger.debug("try to read content for {}", request);
    return new InputStreamWrapper(getLoader(request));
  }

  void getContent(org.eclipse.jgit.lib.Repository repo, ObjectId revId, String path, OutputStream output) throws IOException, PathNotFoundException, RevisionNotFoundException {
    try (ClosableObjectLoaderContainer closableObjectLoaderContainer = getLoader(repo, revId, path)) {
      closableObjectLoaderContainer.objectLoader.copyTo(output);
    }
  }

  private ClosableObjectLoaderContainer getLoader(CatCommandRequest request) throws IOException, PathNotFoundException, RevisionNotFoundException {
    org.eclipse.jgit.lib.Repository repo = open();
    ObjectId revId = getCommitOrDefault(repo, request.getRevision());
    return getLoader(repo, revId, request.getPath());
  }

  private ClosableObjectLoaderContainer getLoader(Repository repo, ObjectId revId, String path) throws IOException, PathNotFoundException, RevisionNotFoundException {
    TreeWalk treeWalk = new TreeWalk(repo);
    treeWalk.setRecursive(Util.nonNull(path).contains("/"));

    logger.debug("load content for {} at {}", path, revId.name());

    RevWalk revWalk = new RevWalk(repo);

    RevCommit entry = null;
    try {
      entry = revWalk.parseCommit(revId);
    } catch (MissingObjectException e) {
      throw new RevisionNotFoundException(revId.getName());
    }
    RevTree revTree = entry.getTree();

    if (revTree != null) {
      treeWalk.addTree(revTree);
    } else {
      logger.error("could not find tree for {}", revId.name());
    }

    treeWalk.setFilter(PathFilter.create(path));

    if (treeWalk.next() && treeWalk.getFileMode(0).getObjectType() == Constants.OBJ_BLOB) {
      ObjectId blobId = treeWalk.getObjectId(0);
      ObjectLoader loader = repo.open(blobId);

      return new ClosableObjectLoaderContainer(loader, treeWalk, revWalk);
    } else {
      throw new PathNotFoundException(path);
    }
  }

  private static class ClosableObjectLoaderContainer implements Closeable {
    private final ObjectLoader objectLoader;
    private final TreeWalk treeWalk;
    private final RevWalk revWalk;

    private ClosableObjectLoaderContainer(ObjectLoader objectLoader, TreeWalk treeWalk, RevWalk revWalk) {
      this.objectLoader = objectLoader;
      this.treeWalk = treeWalk;
      this.revWalk = revWalk;
    }

    @Override
    public void close() {
      GitUtil.release(revWalk);
      GitUtil.release(treeWalk);
    }
  }

  private static class InputStreamWrapper extends FilterInputStream {

    private final ClosableObjectLoaderContainer container;

    private InputStreamWrapper(ClosableObjectLoaderContainer container) throws IOException {
      super(container.objectLoader.openStream());
      this.container = container;
    }

    @Override
    public void close() throws IOException {
      try {
        super.close();
      } finally {
        container.close();
      }
    }
  }
}
