/**
 * Copyright (c) 2010, Sebastian Sdorra All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. Neither the name of SCM-Manager;
 * nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * http://bitbucket.org/sdorra/scm-manager
 *
 */



package sonia.scm.repository.spi;

//~--- non-JDK imports --------------------------------------------------------

import com.aragost.javahg.Repository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.HgHookManager;
import sonia.scm.repository.HgRepositoryHandler;
import sonia.scm.repository.RepositoryHookType;
import sonia.scm.repository.spi.javahg.HgLogChangesetCommand;
import sonia.scm.web.HgUtil;

import java.io.File;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 */
public class HgHookChangesetProvider implements HookChangesetProvider
{

  /**
   * the logger for HgHookChangesetProvider
   */
  private static final Logger logger =
    LoggerFactory.getLogger(HgHookChangesetProvider.class);

  //~--- constructors ---------------------------------------------------------

  public HgHookChangesetProvider(HgRepositoryHandler handler,
    File repositoryDirectory, HgHookManager hookManager, String startRev,
    RepositoryHookType type)
  {
    this.handler = handler;
    this.repositoryDirectory = repositoryDirectory;
    this.hookManager = hookManager;
    this.startRev = startRev;
    this.type = type;
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param request
   *
   * @return
   */
  @Override
  public synchronized HookChangesetResponse handleRequest(HookChangesetRequest request)
  {
    if (response == null)
    {
      Repository repository = null;

      try
      {
        repository = open();

        HgLogChangesetCommand cmd = HgLogChangesetCommand.on(repository,
                                      handler.getConfig());

        response = new HookChangesetResponse(
          cmd.rev(startRev.concat(":").concat(HgUtil.REVISION_TIP)).execute());
      }
      catch (Exception ex)
      {
        logger.error("could not retrieve changesets", ex);
      }
      finally
      {
        if (repository != null)
        {
          repository.close();
        }
      }
    }

    return response;
  }

  /**
   * Method description
   *
   *
   * @return
   */
  private Repository open()
  {
    // use HG_PENDING only for pre receive hooks
    boolean pending = type == RepositoryHookType.PRE_RECEIVE;

    // TODO get repository encoding
    return HgUtil.open(handler, hookManager, repositoryDirectory, null,
      pending);
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private HgRepositoryHandler handler;

  /** Field description */
  private HgHookManager hookManager;

  /** Field description */
  private File repositoryDirectory;

  /** Field description */
  private HookChangesetResponse response;

  /** Field description */
  private String startRev;

  /** Field description */
  private RepositoryHookType type;
}
