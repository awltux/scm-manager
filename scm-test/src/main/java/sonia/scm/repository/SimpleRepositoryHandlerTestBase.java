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
import sonia.scm.AbstractTestBase;
import sonia.scm.AlreadyExistsException;
import sonia.scm.store.ConfigurationStoreFactory;
import sonia.scm.store.InMemoryConfigurationStoreFactory;
import sonia.scm.util.IOUtil;

import java.io.File;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 */
public abstract class SimpleRepositoryHandlerTestBase extends AbstractTestBase {


  protected abstract void checkDirectory(File directory);

  protected abstract RepositoryHandler createRepositoryHandler(
    ConfigurationStoreFactory factory, File directory);

  @Test
  public void testCreate() throws AlreadyExistsException {
    createRepository();
  }

  @Test
  public void testCreateResourcePath() throws AlreadyExistsException {
    Repository repository = createRepository();
    String path = handler.createResourcePath(repository);

    assertNotNull(path);
    assertTrue(path.trim().length() > 0);
    assertTrue(path.contains(repository.getId()));
  }

  @Test
  public void testDelete() throws Exception {
    Repository repository = createRepository();

    handler.delete(repository);

    File directory = new File(baseDirectory, repository.getId());

    assertFalse(directory.exists());
  }

  @Override
  protected void postSetUp() {
    InMemoryConfigurationStoreFactory storeFactory = new InMemoryConfigurationStoreFactory();
    baseDirectory = new File(contextProvider.getBaseDirectory(), "repositories");
    IOUtil.mkdirs(baseDirectory);
    handler = createRepositoryHandler(storeFactory, baseDirectory);
  }

  @Override
  protected void preTearDown() throws Exception {
    if (handler != null) {
      handler.close();
    }
  }

  private Repository createRepository() throws AlreadyExistsException {
    Repository repository = RepositoryTestData.createHeartOfGold();

    handler.create(repository);

    File directory = new File(baseDirectory, repository.getId());

    assertTrue(directory.exists());
    assertTrue(directory.isDirectory());
    checkDirectory(directory);

    return repository;
  }

  protected File baseDirectory;

  private RepositoryHandler handler;
}
