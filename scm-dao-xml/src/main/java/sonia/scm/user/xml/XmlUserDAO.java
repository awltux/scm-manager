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


package sonia.scm.user.xml;

//~--- non-JDK imports --------------------------------------------------------

import com.google.inject.Inject;
import com.google.inject.Singleton;
import sonia.scm.store.ConfigurationStoreFactory;
import sonia.scm.user.User;
import sonia.scm.user.UserDAO;
import sonia.scm.xml.AbstractXmlDAO;

/**
 *
 * @author Sebastian Sdorra
 */
@Singleton
public class XmlUserDAO extends AbstractXmlDAO<User, XmlUserDatabase>
        implements UserDAO
{

  /** Field description */
  public static final String STORE_NAME = "users";

  //~--- constructors ---------------------------------------------------------

  /**
   * Constructs ...
   *
   *
   * @param storeFactory
   */
  @Inject
  public XmlUserDAO(ConfigurationStoreFactory storeFactory)
  {
    super(storeFactory
      .withType(XmlUserDatabase.class)
      .withName(STORE_NAME)
      .build());
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param user
   *
   * @return
   */
  @Override
  protected User clone(User user)
  {
    return user.clone();
  }

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  protected XmlUserDatabase createNewDatabase()
  {
    return new XmlUserDatabase();
  }
}
