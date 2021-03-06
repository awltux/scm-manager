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


package sonia.scm.repository.client.api;

//~--- non-JDK imports --------------------------------------------------------

import com.google.common.collect.Lists;

import sonia.scm.repository.client.spi.RepositoryClientFactoryProvider;
import sonia.scm.util.ServiceUtil;

//~--- JDK imports ------------------------------------------------------------

import java.io.File;
import java.io.IOException;

import java.util.List;

/**
 *
 * @author Sebastian Sdorra
 * @since 1.18
 */
public final class RepositoryClientFactory
{

  /**
   * Constructs ...
   *
   */
  public RepositoryClientFactory()
  {
    this.providers =
      ServiceUtil.getServices(RepositoryClientFactoryProvider.class);
  }

  /**
   * Constructs ...
   *
   *
   * @param provider
   *
   * @param providers
   */
  public RepositoryClientFactory(
    Iterable<RepositoryClientFactoryProvider> providers)
  {
    this.providers = providers;
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   *
   * @param type
   * @param main
   * @param workingCopy
   *
   * @return
   *
   * @throws IOException
   */
  public RepositoryClient create(String type, File main, File workingCopy)
    throws IOException
  {

    return new RepositoryClient(getProvider(type).create(main, workingCopy));
  }

  /**
   * Method description
   *
   *
   *
   * @param type
   * @param url
   * @param username
   * @param password
   * @param workingCopy
   *
   * @return
   *
   * @throws IOException
   */
  public RepositoryClient create(String type, String url, String username,
    String password, File workingCopy)
    throws IOException
  {
    return new RepositoryClient(getProvider(type).create(url, username,
      password, workingCopy));
  }

  public RepositoryClient create(String type, String url, File workingCopy)
    throws IOException
  {
    return new RepositoryClient(getProvider(type).create(url, null, null, workingCopy));
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  public Iterable<String> getAvailableTypes()
  {
    List<String> types = Lists.newArrayList();

    for (RepositoryClientFactoryProvider provider : providers)
    {
      types.add(provider.getType());
    }

    return types;
  }

  /**
   * Method description
   *
   *
   * @param type
   *
   * @return
   */
  private RepositoryClientFactoryProvider getProvider(String type)
  {
    RepositoryClientFactoryProvider provider = null;

    for (RepositoryClientFactoryProvider p : providers)
    {
      if (p.getType().equalsIgnoreCase(type))
      {
        provider = p;

        break;
      }
    }

    if (provider == null)
    {
      throw new RuntimeException(
        "could not find provider for type ".concat(type));
    }

    return provider;
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private Iterable<RepositoryClientFactoryProvider> providers;
}
