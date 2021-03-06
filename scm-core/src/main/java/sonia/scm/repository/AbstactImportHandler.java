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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.ImportResult.Builder;

import java.io.File;
import java.io.IOException;
import java.util.List;

//~--- JDK imports ------------------------------------------------------------

/**
 * Abstract base class for directory based {@link ImportHandler} and
 * {@link AdvancedImportHandler}.
 *
 * @author Sebastian Sdorra
 * @since 1.12
 */
public abstract class AbstactImportHandler implements AdvancedImportHandler
{

  /**
   * the logger for AbstactImportHandler
   */
  private static final Logger logger =
    LoggerFactory.getLogger(AbstactImportHandler.class);

  //~--- get methods ----------------------------------------------------------

  /**
   * Returns array of repository directory names.
   *
   *
   * @return repository directory names
   */
  protected abstract String[] getDirectoryNames();

  /**
   * Returns repository handler.
   *
   *
   * @return repository handler
   */
  protected abstract AbstractRepositoryHandler<?> getRepositoryHandler();

  //~--- methods --------------------------------------------------------------

  /**
   * {@inheritDoc}
   */
  @Override
  public List<String> importRepositories(RepositoryManager manager) throws IOException {
    return doRepositoryImport(manager, true).getImportedDirectories();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public ImportResult importRepositoriesFromDirectory(RepositoryManager manager)
  {
    return doRepositoryImport(manager, false);
  }

  /**
   * Creates a repository.
   *
   *
   * @param repositoryDirectory repository base directory
   * @param repositoryName name of the repository
   *
   * @return repository
   *
   * @throws IOException
   */
  protected Repository createRepository(File repositoryDirectory, String repositoryName) throws IOException {
    Repository repository = new Repository();

    repository.setName(repositoryName);
    repository.setType(getTypeName());

    return repository;
  }

  /**
   * Repository import.
   *
   *
   * @param manager repository manager
   * @param throwExceptions true to throw exception
   *
   * @return import result
   *
   * @throws IOException
   */
  private ImportResult doRepositoryImport(RepositoryManager manager, boolean throwExceptions) {
    Builder builder = ImportResult.builder();

    logger.trace("search for repositories to import");

    // TODO #8783
//    try
//    {
//
//      List<String> repositoryNames =
//        RepositoryUtil.getRepositoryNames(getRepositoryHandler(),
//          getDirectoryNames());
//
//      for (String repositoryName : repositoryNames)
//      {
//        importRepository(manager, builder, throwExceptions, repositoryName);
//      }
//
//    }
//    catch (IOException ex)
//    {
//      handleException(ex, throwExceptions);
//    }

    return builder.build();
  }

  /**
   * Method description
   *
   *
   * @param ex
   * @param throwExceptions
   * @param <T>
   *
   * @throws T
   */
  private <T extends Exception> void handleException(T ex,
    boolean throwExceptions)
    throws T
  {
    logger.warn("error durring repository directory import", ex);

    if (throwExceptions)
    {
      throw ex;
    }
  }

  /**
   * Method description
   *
   *
   * @param manager
   * @param builder
   * @param throwExceptions
   * @param directoryName
   *
   * @throws IOException
   */
  private void importRepository(RepositoryManager manager, Builder builder,
    boolean throwExceptions, String directoryName)
    throws IOException
  {
    logger.trace("check repository {} for import", directoryName);

    // TODO #8783
//
//    Repository repository = manager.get(namespaceAndName);
//
//    if (repository == null)
//    {
//      try
//      {
//        importRepository(manager, repositoryName);
//        builder.addImportedDirectory(repositoryName);
//      }
//      catch (IOException ex)
//      {
//        builder.addFailedDirectory(repositoryName);
//        handleException(ex, throwExceptions);
//      }
//      catch (IllegalStateException ex)
//      {
//        builder.addFailedDirectory(repositoryName);
//        handleException(ex, throwExceptions);
//      }
//      catch (RepositoryException ex)
//      {
//        builder.addFailedDirectory(repositoryName);
//        handleException(ex, throwExceptions);
//      }
//    }
//    else if (logger.isDebugEnabled())
//    {
//      logger.debug("repository {} is already managed", repositoryName);
//    }
  }



  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  private String getTypeName()
  {
    return getRepositoryHandler().getType().getName();
  }
}
