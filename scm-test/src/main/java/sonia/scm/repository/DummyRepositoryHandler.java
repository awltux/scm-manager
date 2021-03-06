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

import com.google.common.collect.Sets;
import sonia.scm.AlreadyExistsException;
import sonia.scm.store.ConfigurationStoreFactory;

import javax.xml.bind.annotation.XmlRootElement;
import java.io.File;
import java.util.HashSet;
import java.util.Set;

//~--- JDK imports ------------------------------------------------------------

/**
 * @author Sebastian Sdorra
 */
public class DummyRepositoryHandler
  extends AbstractSimpleRepositoryHandler<DummyRepositoryHandler.DummyRepositoryConfig> {

  public static final String TYPE_DISPLAYNAME = "Dummy";

  public static final String TYPE_NAME = "dummy";

  public static final RepositoryType TYPE = new RepositoryType(TYPE_NAME, TYPE_DISPLAYNAME, Sets.newHashSet());

  private final Set<String> existingRepoNames = new HashSet<>();

  public DummyRepositoryHandler(ConfigurationStoreFactory storeFactory, RepositoryLocationResolver repositoryLocationResolver) {
    super(storeFactory, repositoryLocationResolver, null);
  }

  @Override
  public RepositoryType getType() {
    return TYPE;
  }


  @Override
  protected void create(Repository repository, File directory) {
    String key = repository.getNamespace() + "/" + repository.getName();
    if (existingRepoNames.contains(key)) {
      throw new AlreadyExistsException(repository);
    } else {
      existingRepoNames.add(key);
    }
  }

  @Override
  protected DummyRepositoryConfig createInitialConfig() {
    return new DummyRepositoryConfig();
  }

  @Override
  protected Class<DummyRepositoryConfig> getConfigClass() {
    return DummyRepositoryConfig.class;
  }

  @XmlRootElement(name = "config")
  public static class DummyRepositoryConfig extends RepositoryConfig {
    @Override
    public String getId() {
      return TYPE_NAME;
    }
  }
}
