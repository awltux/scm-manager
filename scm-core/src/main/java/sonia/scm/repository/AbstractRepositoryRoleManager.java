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

import sonia.scm.HandlerEventType;
import sonia.scm.event.ScmEventBus;

/**
 * Abstract base class for {@link RepositoryRoleManager} implementations. This class
 * implements the listener methods of the {@link RepositoryRoleManager} interface.
 */
public abstract class AbstractRepositoryRoleManager implements RepositoryRoleManager {

  /**
   * Send a {@link RepositoryRoleEvent} to the {@link ScmEventBus}.
   *
   * @param event type of change event
   * @param repositoryRole repositoryRole that has changed
   * @param oldRepositoryRole old repositoryRole
   */
  protected void fireEvent(HandlerEventType event, RepositoryRole repositoryRole, RepositoryRole oldRepositoryRole)
  {
    fireEvent(new RepositoryRoleModificationEvent(event, repositoryRole, oldRepositoryRole));
  }

  /**
   * Creates a new {@link RepositoryRoleEvent} and calls {@link #fireEvent(RepositoryRoleEvent)}.
   *
   * @param repositoryRole repositoryRole that has changed
   * @param event type of change event
   */
  protected void fireEvent(HandlerEventType event, RepositoryRole repositoryRole)
  {
    fireEvent(new RepositoryRoleEvent(event, repositoryRole));
  }

  /**
   * Send a {@link RepositoryRoleEvent} to the {@link ScmEventBus}.
   *
   * @param event repositoryRole event
   * @since 1.48
   */  
  protected void fireEvent(RepositoryRoleEvent event)
  {
    ScmEventBus.getInstance().post(event);
  }
}
