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

//~--- non-JDK imports --------------------------------------------------------

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
/**
 *
 * @author Sebastian Sdorra
 * @since 1.31
 */
public abstract class PagedRemoteCommandRequest extends RemoteCommandRequest
{

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean equals(Object obj)
  {
    if (obj == null)
    {
      return false;
    }

    if (getClass() != obj.getClass())
    {
      return false;
    }

    final PagedRemoteCommandRequest other = (PagedRemoteCommandRequest) obj;

    return Objects.equal(remoteRepository, other.remoteRepository)
      && Objects.equal(pagingStart, other.pagingStart)
      && Objects.equal(pagingLimit, other.pagingLimit);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public int hashCode()
  {
    return Objects.hashCode(remoteRepository, pagingStart, pagingLimit);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String toString()
  {

    //J-
    return MoreObjects.toStringHelper(this)
                  .add("remoteURL", remoteRepository)
                  .add("pagingStart", pagingStart)
                  .add("pagingLimit", pagingLimit)
                  .toString();
    //J+
  }

  //~--- set methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param pagingLimit
   */
  public void setPagingLimit(int pagingLimit)
  {
    this.pagingLimit = pagingLimit;
  }

  /**
   * Method description
   *
   *
   * @param pagingStart
   */
  public void setPagingStart(int pagingStart)
  {
    this.pagingStart = pagingStart;
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  int getPagingLimit()
  {
    return pagingLimit;
  }

  /**
   * Method description
   *
   *
   * @return
   */
  int getPagingStart()
  {
    return pagingStart;
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private int pagingLimit = 20;

  /** Field description */
  private int pagingStart = 0;
}
