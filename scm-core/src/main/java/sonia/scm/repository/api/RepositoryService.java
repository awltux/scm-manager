/**
 * Copyright (c) 2010, Sebastian Sdorra
 * All rights reserved.
 * <p>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * <p>
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 3. Neither the name of SCM-Manager; nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * <p>
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
 * <p>
 * http://bitbucket.org/sdorra/scm-manager
 */


package sonia.scm.repository.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.cache.CacheManager;
import sonia.scm.repository.Changeset;
import sonia.scm.repository.Feature;
import sonia.scm.repository.PreProcessorUtil;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryPermissions;
import sonia.scm.repository.spi.RepositoryServiceProvider;

import java.io.Closeable;
import java.io.IOException;
import java.util.Set;
import java.util.stream.Stream;

/**
 * From the {@link RepositoryService} it is possible to access all commands for
 * a single {@link Repository}. The {@link RepositoryService} is only access
 * able from the {@link RepositoryServiceFactory}.<br />
 * <br />
 *
 * <b>Note:</b> Not every {@link RepositoryService} supports every command. If
 * the command is not supported the method will trow a
 * {@link CommandNotSupportedException}. It is possible to check if the command
 * is supported by the {@link RepositoryService} with the
 * {@link RepositoryService#isSupported(Command)} method.<br />
 * <br />
 *
 * <b>Warning:</b> You should always close the connection to the repository
 * after work is finished. For closing the connection to the repository use the
 * {@link #close()} method.
 *
 * @author Sebastian Sdorra
 * @apiviz.uses sonia.scm.repository.Feature
 * @apiviz.uses sonia.scm.repository.api.Command
 * @apiviz.uses sonia.scm.repository.api.BlameCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.BrowseCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.CatCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.DiffCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.LogCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.TagsCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.BranchesCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.IncomingCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.OutgoingCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.PullCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.PushCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.BundleCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.UnbundleCommandBuilder
 * @apiviz.uses sonia.scm.repository.api.MergeCommandBuilder
 * @since 1.17
 */
public final class RepositoryService implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(RepositoryService.class);

  private final CacheManager cacheManager;
  private final PreProcessorUtil preProcessorUtil;
  private final RepositoryServiceProvider provider;
  private final Repository repository;
  private final Set<ScmProtocolProvider> protocolProviders;

  /**
   * Constructs a new {@link RepositoryService}. This constructor should only
   * be called from the {@link RepositoryServiceFactory}.
   *  @param cacheManager     cache manager
   * @param provider         implementation for {@link RepositoryServiceProvider}
   * @param repository       the repository
   */
  RepositoryService(CacheManager cacheManager,
    RepositoryServiceProvider provider, Repository repository,
    PreProcessorUtil preProcessorUtil, Set<ScmProtocolProvider> protocolProviders) {
    this.cacheManager = cacheManager;
    this.provider = provider;
    this.repository = repository;
    this.preProcessorUtil = preProcessorUtil;
    this.protocolProviders = protocolProviders;
  }

  /**
   * Closes the connection to the repository and releases all locks
   * and resources. This method should be called in a finally block e.g.:
   *
   * <pre><code>
   * RepositoryService service = null;
   * try {
   *   service = factory.create("repositoryId");
   *   // do something with the service
   * } finally {
   *   if ( service != null ){
   *     service.close();
   *   }
   * }
   * </code></pre>
   */
  @Override
  public void close() {
    try {
      provider.close();
    } catch (IOException ex) {
      LOG.error("Could not close repository service provider", ex);
    }
  }

  /**
   * The blame command shows changeset information by line for a given file.
   *
   * @return instance of {@link BlameCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public BlameCommandBuilder getBlameCommand() {
    LOG.debug("create blame command for repository {}",
      repository.getNamespaceAndName());

    return new BlameCommandBuilder(cacheManager, provider.getBlameCommand(),
      repository, preProcessorUtil);
  }

  /**
   * The branches command list all repository branches.
   *
   * @return instance of {@link BranchesCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public BranchesCommandBuilder getBranchesCommand() {
    LOG.debug("create branches command for repository {}",
      repository.getNamespaceAndName());

    return new BranchesCommandBuilder(cacheManager,
      provider.getBranchesCommand(), repository);
  }

  /**
   * The branch command creates new branches.
   *
   * @return instance of {@link BranchCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public BranchCommandBuilder getBranchCommand() {
    RepositoryPermissions.push(getRepository()).check();
    LOG.debug("create branch command for repository {}",
      repository.getNamespaceAndName());

    return new BranchCommandBuilder(provider.getBranchCommand());
  }

  /**
   * The browse command allows browsing of a repository.
   *
   * @return instance of {@link BrowseCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public BrowseCommandBuilder getBrowseCommand() {
    LOG.debug("create browse command for repository {}",
      repository.getNamespaceAndName());

    return new BrowseCommandBuilder(cacheManager, provider.getBrowseCommand(),
      repository, preProcessorUtil);
  }

  /**
   * The bundle command creates an archive from the repository.
   *
   * @return instance of {@link BundleCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   * @since 1.43
   */
  public BundleCommandBuilder getBundleCommand() {
    LOG.debug("create bundle command for repository {}",
      repository.getNamespaceAndName());

    return new BundleCommandBuilder(provider.getBundleCommand(), repository);
  }

  /**
   * The cat command show the content of a given file.
   *
   * @return instance of {@link CatCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public CatCommandBuilder getCatCommand() {
    LOG.debug("create cat command for repository {}",
      repository.getNamespaceAndName());

    return new CatCommandBuilder(provider.getCatCommand());
  }

  /**
   * The diff command shows differences between revisions for a specified file
   * or the entire revision.
   *
   * @return instance of {@link DiffCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public DiffCommandBuilder getDiffCommand() {
    LOG.debug("create diff command for repository {}",
      repository.getNamespaceAndName());

    return new DiffCommandBuilder(provider.getDiffCommand(), provider.getSupportedFeatures());
  }

  /**
   * The diff command shows differences between revisions for a specified file
   * or the entire revision.
   *
   * @return instance of {@link DiffResultCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public DiffResultCommandBuilder getDiffResultCommand() {
    LOG.debug("create diff result command for repository {}",
      repository.getNamespaceAndName());

    return new DiffResultCommandBuilder(provider.getDiffResultCommand(), provider.getSupportedFeatures());
  }

  /**
   * The incoming command shows new {@link Changeset}s found in a different
   * repository location.
   *
   * @return instance of {@link IncomingCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   * @since 1.31
   */
  public IncomingCommandBuilder getIncomingCommand() {
    LOG.debug("create incoming command for repository {}",
      repository.getNamespaceAndName());

    return new IncomingCommandBuilder(cacheManager,
      provider.getIncomingCommand(), repository, preProcessorUtil);
  }

  /**
   * The log command shows revision history of entire repository or files.
   *
   * @return instance of {@link LogCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public LogCommandBuilder getLogCommand() {
    LOG.debug("create log command for repository {}",
      repository.getNamespaceAndName());

    return new LogCommandBuilder(cacheManager, provider.getLogCommand(),
      repository, preProcessorUtil, provider.getSupportedFeatures());
  }

  /**
   * The modification command shows file modifications in a revision.
   *
   * @return instance of {@link ModificationsCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public ModificationsCommandBuilder getModificationsCommand() {
    LOG.debug("create modifications command for repository {}", repository.getNamespaceAndName());
    return new ModificationsCommandBuilder(provider.getModificationsCommand(),repository, cacheManager.getCache(ModificationsCommandBuilder.CACHE_NAME), preProcessorUtil);
  }

  /**
   * The outgoing command show {@link Changeset}s not found in a remote repository.
   *
   * @return instance of {@link OutgoingCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   * @since 1.31
   */
  public OutgoingCommandBuilder getOutgoingCommand() {
    LOG.debug("create outgoing command for repository {}",
      repository.getNamespaceAndName());

    return new OutgoingCommandBuilder(cacheManager,
      provider.getOutgoingCommand(), repository, preProcessorUtil);
  }

  /**
   * The pull command pull changes from a other repository.
   *
   * @return instance of {@link PullCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   * @since 1.31
   */
  public PullCommandBuilder getPullCommand() {
    LOG.debug("create pull command for repository {}",
      repository.getNamespaceAndName());

    return new PullCommandBuilder(provider.getPullCommand(), repository);
  }

  /**
   * The push command pushes changes to a other repository.
   *
   * @return instance of {@link PushCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   * @since 1.31
   */
  public PushCommandBuilder getPushCommand() {
    LOG.debug("create push command for repository {}",
      repository.getNamespaceAndName());

    return new PushCommandBuilder(provider.getPushCommand());
  }

  /**
   * Returns the repository of this service.
   *
   * @return repository of this service
   */
  public Repository getRepository() {
    return repository;
  }

  /**
   * The tags command list all repository tag.
   *
   * @return instance of {@link TagsCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   */
  public TagsCommandBuilder getTagsCommand() {
    LOG.debug("create tags command for repository {}",
      repository.getNamespaceAndName());

    return new TagsCommandBuilder(cacheManager, provider.getTagsCommand(),
      repository);
  }

  /**
   * The unbundle command restores a repository from the given bundle.
   *
   * @return instance of {@link UnbundleCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   * @since 1.43
   */
  public UnbundleCommandBuilder getUnbundleCommand() {
    LOG.debug("create unbundle command for repository {}",
      repository.getNamespaceAndName());

    return new UnbundleCommandBuilder(provider.getUnbundleCommand(),
      repository);
  }

  /**
   * The merge command executes a merge of two branches. It is possible to do a dry run to check, whether the given
   * branches can be merged without conflicts.
   *
   * @return instance of {@link MergeCommandBuilder}
   * @throws CommandNotSupportedException if the command is not supported
   *                                      by the implementation of the repository service provider.
   * @since 2.0.0
   */
  public MergeCommandBuilder getMergeCommand() {
    LOG.debug("create merge command for repository {}",
      repository.getNamespaceAndName());

    return new MergeCommandBuilder(provider.getMergeCommand());
  }

  /**
   * Returns true if the command is supported by the repository service.
   *
   * @param command command
   * @return true if the command is supported
   */
  public boolean isSupported(Command command) {
    return provider.getSupportedCommands().contains(command);
  }

  /**
   * Returns true if the feature is supported by the repository service.
   *
   * @param feature feature
   * @return true if the feature is supported
   * @since 1.25
   */
  public boolean isSupported(Feature feature) {
    return provider.getSupportedFeatures().contains(feature);
  }

  public <T extends ScmProtocol> Stream<T> getSupportedProtocols() {
    return protocolProviders.stream()
      .filter(protocolProvider -> protocolProvider.getType().equals(getRepository().getType()))
      .map(this::<T>createProviderInstanceForRepository);
  }

  private <T extends ScmProtocol> T createProviderInstanceForRepository(ScmProtocolProvider<T> protocolProvider) {
    return protocolProvider.get(repository);
  }

  public <T extends ScmProtocol> T getProtocol(Class<T> clazz) {
    return this.<T>getSupportedProtocols()
      .filter(scmProtocol -> clazz.isAssignableFrom(scmProtocol.getClass()))
      .findFirst()
      .orElseThrow(() -> new IllegalArgumentException(String.format("no implementation for %s and repository type %s", clazz.getName(),getRepository().getType())));
  }
}
