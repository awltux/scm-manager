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


package sonia.scm.repository;

//~--- non-JDK imports --------------------------------------------------------

import org.junit.Test;
import org.mockito.stubbing.Answer;
import sonia.scm.AbstractTestBase;
import sonia.scm.store.ConfigurationStoreFactory;
import sonia.scm.store.InMemoryConfigurationStoreFactory;
import sonia.scm.util.IOUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

//~--- JDK imports ------------------------------------------------------------

/**
 * @author Sebastian Sdorra
 */
public abstract class SimpleRepositoryHandlerTestBase extends AbstractTestBase {


  protected RepositoryDAO repoDao = mock(RepositoryDAO.class);
  protected Path repoPath;
  protected Repository repository;

  protected abstract void checkDirectory(File directory);

  protected abstract RepositoryHandler createRepositoryHandler(
    ConfigurationStoreFactory factory, RepositoryLocationResolver locationResolver, File directory) throws IOException, RepositoryPathNotFoundException;

  @Test
  public void testCreate() {
    createRepository();
  }

  @Override
  protected void postSetUp() throws IOException, RepositoryPathNotFoundException {
    InMemoryConfigurationStoreFactory storeFactory = new InMemoryConfigurationStoreFactory();
    baseDirectory = new File(contextProvider.getBaseDirectory(), "repositories");
    IOUtil.mkdirs(baseDirectory);

    locationResolver = mock(RepositoryLocationResolver.class);

    RepositoryLocationResolver.RepositoryLocationResolverInstance instanceMock = mock(RepositoryLocationResolver.RepositoryLocationResolverInstance.class);
    when(locationResolver.create(any())).thenReturn(instanceMock);
    when(locationResolver.supportsLocationType(any())).thenReturn(true);
    Answer<Object> pathAnswer = ic -> {
      String id = ic.getArgument(0);
      return baseDirectory.toPath().resolve(id);
    };
    when(instanceMock.getLocation(anyString())).then(pathAnswer);
    when(instanceMock.createLocation(anyString())).then(pathAnswer);

    handler = createRepositoryHandler(storeFactory, locationResolver, baseDirectory);
  }

  @Override
  protected void preTearDown() throws Exception {
    if (handler != null) {
      handler.close();
    }
  }

  private void createRepository() {
    File nativeRepoDirectory = initRepository();

    handler.create(repository);

    assertTrue(nativeRepoDirectory.exists());
    assertTrue(nativeRepoDirectory.isDirectory());
    checkDirectory(nativeRepoDirectory);
  }

  protected File initRepository() {
    repository = RepositoryTestData.createHeartOfGold();
    File repoDirectory = new File(baseDirectory, repository.getId());
    repoPath = repoDirectory.toPath();
//    when(repoDao.getPath(repository.getId())).thenReturn(repoPath);
    return new File(repoDirectory, RepositoryDirectoryHandler.REPOSITORIES_NATIVE_DIRECTORY);
  }

  protected File baseDirectory;
  protected RepositoryLocationResolver locationResolver;

  private RepositoryHandler handler;
}
