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

import com.google.common.collect.ImmutableSet;
import sonia.scm.api.v2.resources.GitRepositoryConfigStoreProvider;
import sonia.scm.event.ScmEventBus;
import sonia.scm.repository.Feature;
import sonia.scm.repository.GitRepositoryHandler;
import sonia.scm.repository.Repository;
import sonia.scm.repository.api.Command;
import sonia.scm.repository.api.HookContextFactory;
import sonia.scm.web.lfs.LfsBlobStoreFactory;

import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 */
public class GitRepositoryServiceProvider extends RepositoryServiceProvider
{

  /** Field description */
  //J-
  public static final Set<Command> COMMANDS = ImmutableSet.of(
    Command.BLAME,
    Command.BROWSE,
    Command.CAT,
    Command.DIFF,
    Command.DIFF_RESULT,
    Command.LOG,
    Command.TAGS,
    Command.BRANCH,
    Command.BRANCHES, 
    Command.INCOMING,
    Command.OUTGOING,
    Command.PUSH,
    Command.PULL,
    Command.MERGE,
    Command.MODIFY
  );
  protected static final Set<Feature> FEATURES = EnumSet.of(Feature.INCOMING_REVISION);
  //J+

  //~--- constructors ---------------------------------------------------------

  public GitRepositoryServiceProvider(GitRepositoryHandler handler, Repository repository, GitRepositoryConfigStoreProvider storeProvider, LfsBlobStoreFactory lfsBlobStoreFactory, HookContextFactory hookContextFactory, ScmEventBus eventBus, SyncAsyncExecutorProvider executorProvider) {
    this.handler = handler;
    this.repository = repository;
    this.lfsBlobStoreFactory = lfsBlobStoreFactory;
    this.hookContextFactory = hookContextFactory;
    this.eventBus = eventBus;
    this.executorProvider = executorProvider;
    this.context = new GitContext(handler.getDirectory(repository.getId()), repository, storeProvider);
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @throws IOException
   */
  @Override
  public void close() throws IOException
  {
    context.close();
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public BlameCommand getBlameCommand()
  {
    return new GitBlameCommand(context, repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public BranchesCommand getBranchesCommand()
  {
    return new GitBranchesCommand(context, repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public BranchCommand getBranchCommand()
  {
    return new GitBranchCommand(context, repository, hookContextFactory, eventBus);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public BrowseCommand getBrowseCommand()
  {
    return new GitBrowseCommand(context, repository, lfsBlobStoreFactory, executorProvider.createExecutorWithDefaultTimeout());
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public CatCommand getCatCommand()
  {
    return new GitCatCommand(context, repository, lfsBlobStoreFactory);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public DiffCommand getDiffCommand()
  {
    return new GitDiffCommand(context, repository);
  }

  @Override
  public DiffResultCommand getDiffResultCommand() {
    return new GitDiffResultCommand(context, repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public IncomingCommand getIncomingCommand()
  {
    return new GitIncomingCommand(handler, context, repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public LogCommand getLogCommand()
  {
    return new GitLogCommand(context, repository);
  }

  @Override
  public ModificationsCommand getModificationsCommand() {
    return new GitModificationsCommand(context,repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public OutgoingCommand getOutgoingCommand()
  {
    return new GitOutgoingCommand(handler, context, repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public PullCommand getPullCommand()
  {
    return new GitPullCommand(handler, context, repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public PushCommand getPushCommand()
  {
    return new GitPushCommand(handler, context, repository);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public Set<Command> getSupportedCommands()
  {
    return COMMANDS;
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public TagsCommand getTagsCommand()
  {
    return new GitTagsCommand(context, repository);
  }

  @Override
  public MergeCommand getMergeCommand() {
    return new GitMergeCommand(context, repository, handler.getWorkdirFactory());
  }

  @Override
  public ModifyCommand getModifyCommand() {
    return new GitModifyCommand(context, repository, handler.getWorkdirFactory(), lfsBlobStoreFactory);
  }

  @Override
  public Set<Feature> getSupportedFeatures() {
    return FEATURES;
  }
//~--- fields ---------------------------------------------------------------

  /** Field description */
  private final GitContext context;

  /** Field description */
  private final GitRepositoryHandler handler;

  /** Field description */
  private final Repository repository;

  private final LfsBlobStoreFactory lfsBlobStoreFactory;

  private final HookContextFactory hookContextFactory;

  private final ScmEventBus eventBus;

  private final SyncAsyncExecutorProvider executorProvider;
}
