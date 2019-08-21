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



package sonia.scm.repository;

//~--- non-JDK imports --------------------------------------------------------

import com.google.common.base.Strings;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.eclipse.jgit.lib.StoredConfig;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.SCMContextProvider;
import sonia.scm.plugin.Extension;
import sonia.scm.plugin.PluginLoader;
import sonia.scm.repository.spi.GitRepositoryServiceProvider;
import sonia.scm.schedule.Scheduler;
import sonia.scm.schedule.Task;
import sonia.scm.store.ConfigurationStoreFactory;

import java.io.File;
import java.io.IOException;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 */
@Singleton
@Extension
public class GitRepositoryHandler
  extends AbstractSimpleRepositoryHandler<GitConfig>
{

  /** Field description */
  public static final String DIRECTORY_REFS = "refs";

  /** Field description */
  public static final String RESOURCE_VERSION =
    "sonia/scm/version/scm-git-plugin";

  /** Field description */
  public static final String TYPE_DISPLAYNAME = "Git";

  /** Field description */
  public static final String TYPE_NAME = "git";


  public static final String DOT_GIT = ".git";

  private static final Logger logger = LoggerFactory.getLogger(GitRepositoryHandler.class);

  /** Field description */
  public static final RepositoryType TYPE = new RepositoryType(TYPE_NAME,
                                    TYPE_DISPLAYNAME,
                                    GitRepositoryServiceProvider.COMMANDS);

  private static final Object LOCK = new Object();

  private final Scheduler scheduler;

  private final GitWorkdirFactory workdirFactory;

  private Task task;

  //~--- constructors ---------------------------------------------------------

  @Inject
  public GitRepositoryHandler(ConfigurationStoreFactory storeFactory,
                              Scheduler scheduler,
                              RepositoryLocationResolver repositoryLocationResolver,
                              GitWorkdirFactory workdirFactory,
                              PluginLoader pluginLoader)
  {
    super(storeFactory, repositoryLocationResolver, pluginLoader);
    this.scheduler = scheduler;
    this.workdirFactory = workdirFactory;
  }

  //~--- get methods ----------------------------------------------------------

  @Override
  public void init(SCMContextProvider context)
  {
    super.init(context);
    scheduleGc(getConfig().getGcExpression());
  }

  @Override
  public void setConfig(GitConfig config)
  {
    scheduleGc(config.getGcExpression());
    super.setConfig(config);
  }

  private void scheduleGc(String expression)
  {
    synchronized (LOCK){
      if ( task != null ){
        logger.debug("cancel existing git gc task");
        task.cancel();
        task = null;
      }
      if (!Strings.isNullOrEmpty(expression))
      {
        logger.info("schedule git gc task with expression {}", expression);
        task = scheduler.schedule(expression, GitGcTask.class);
      }
    }
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public ImportHandler getImportHandler()
  {
    return new GitImportHandler(this);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public RepositoryType getType()
  {
    return TYPE;
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public String getVersionInformation()
  {
    return getStringFromResource(RESOURCE_VERSION, DEFAULT_VERSION_INFORMATION);
  }

  public GitWorkdirFactory getWorkdirFactory() {
    return workdirFactory;
  }

  public String getRepositoryId(StoredConfig gitConfig) {
    return new GitConfigHelper().getRepositoryId(gitConfig);
  }

  //~--- methods --------------------------------------------------------------

  @Override
  protected void create(Repository repository, File directory) throws IOException {
    try (org.eclipse.jgit.lib.Repository gitRepository = build(directory)) {
      gitRepository.create(true);
      new GitConfigHelper().createScmmConfig(repository, gitRepository);
    }
  }

  private org.eclipse.jgit.lib.Repository build(File directory) throws IOException {
    return new FileRepositoryBuilder()
      .setGitDir(directory)
      .readEnvironment()
      .findGitDir()
      .build();
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  protected GitConfig createInitialConfig()
  {
    return new GitConfig();
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  protected Class<GitConfig> getConfigClass()
  {
    return GitConfig.class;
  }
}
