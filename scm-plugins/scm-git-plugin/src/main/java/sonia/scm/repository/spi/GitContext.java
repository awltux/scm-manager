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

//~--- non-JDK imports --------------------------------------------------------

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sonia.scm.api.v2.resources.GitRepositoryConfigStoreProvider;
import sonia.scm.repository.GitRepositoryConfig;
import sonia.scm.repository.GitUtil;
import sonia.scm.repository.Repository;

//~--- JDK imports ------------------------------------------------------------

import java.io.Closeable;
import java.io.File;
import java.io.IOException;

/**
 *
 * @author Sebastian Sdorra
 */
public class GitContext implements Closeable
{

  /**
   * the logger for GitContext
   */
  private static final Logger logger =
    LoggerFactory.getLogger(GitContext.class);

  //~--- constructors ---------------------------------------------------------

  /**
   * Constructs ...
   *
   *
   * @param directory
   * @param repository
   */
  public GitContext(File directory, Repository repository, GitRepositoryConfigStoreProvider storeProvider)
  {
    this.directory = directory;
    this.repository = repository;
    this.storeProvider = storeProvider;
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   */
  @Override
  public void close()
  {
    logger.trace("close git repository {}", directory);

    GitUtil.close(gitRepository);
    gitRepository = null;
  }

  /**
   * Method description
   *
   *
   * @return
   *
   * @throws IOException
   */
  public org.eclipse.jgit.lib.Repository open() throws IOException
  {
    if (gitRepository == null)
    {
      logger.trace("open git repository {}", directory);

      gitRepository = GitUtil.open(directory);
    }

    return gitRepository;
  }

  Repository getRepository() {
    return repository;
  }

  File getDirectory() {
    return directory;
  }

  GitRepositoryConfig getConfig() {
    GitRepositoryConfig config = storeProvider.get(repository).get();
    if (config == null) {
      return new GitRepositoryConfig();
    } else {
      return config;
    }
  }

  void setConfig(GitRepositoryConfig newConfig) {
    storeProvider.get(repository).set(newConfig);
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private final File directory;
  private final Repository repository;
  private final GitRepositoryConfigStoreProvider storeProvider;

  /** Field description */
  private org.eclipse.jgit.lib.Repository gitRepository;
}
