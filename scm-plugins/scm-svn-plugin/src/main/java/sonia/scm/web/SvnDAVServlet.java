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



package sonia.scm.web;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tmatesoft.svn.core.internal.server.dav.DAVConfig;
import org.tmatesoft.svn.core.internal.server.dav.DAVServlet;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryProvider;
import sonia.scm.repository.RepositoryRequestListenerUtil;
import sonia.scm.repository.SvnRepositoryHandler;
import sonia.scm.repository.spi.ScmProviderHttpServlet;
import sonia.scm.util.AssertUtil;
import sonia.scm.util.HttpUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 * @author Sebastian Sdorra
 */
@Singleton
public class SvnDAVServlet extends DAVServlet implements ScmProviderHttpServlet
{

  /** Field description */
  private static final String HEADER_CONTEXTPATH = "X-Forwarded-Ctx";

  /** Field description */
  private static final long serialVersionUID = -1462257085465785945L;

  /** the logger for SvnDAVServlet */
  private static final Logger logger =
    LoggerFactory.getLogger(SvnDAVServlet.class);

  //~--- constructors ---------------------------------------------------------

  /**
   * Constructs ...
   *
   *
   * @param handler
   * @param collectionRenderer
   * @param repositoryProvider
   * @param repositoryRequestListenerUtil
   */
  @Inject
  public SvnDAVServlet(SvnRepositoryHandler handler,
    SvnCollectionRenderer collectionRenderer,
    RepositoryProvider repositoryProvider,
    RepositoryRequestListenerUtil repositoryRequestListenerUtil)
  {
    this.handler = handler;
    this.collectionRenderer = collectionRenderer;
    this.repositoryProvider = repositoryProvider;
    this.repositoryRequestListenerUtil = repositoryRequestListenerUtil;
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param request
   * @param response
   *
   * @throws IOException
   * @throws ServletException
   */
  @Override
  public void service(HttpServletRequest request, HttpServletResponse response, Repository repository)
    throws ServletException, IOException
  {
    if (repositoryRequestListenerUtil.callListeners(request, response,
      repository))
    {
      super.service(new SvnHttpServletRequestWrapper(request,
        repository), response);
    }
    else if (logger.isDebugEnabled())
    {
      logger.debug("request aborted by repository request listener");
    }
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  protected DAVConfig getDAVConfig()
  {
    return new SvnDAVConfig(super.getDAVConfig(), handler, collectionRenderer,
      repositoryProvider);
  }

  //~--- inner classes --------------------------------------------------------

  /**
   * Class description
   *
   *
   * @version        Enter version here..., 11/10/23
   * @author         Enter your name here...
   */
  private static class SvnHttpServletRequestWrapper
    extends HttpServletRequestWrapper
  {

    public SvnHttpServletRequestWrapper(HttpServletRequest request,
      Repository repository)
    {
      super(request);
      this.repository = repository;
    }

    //~--- get methods --------------------------------------------------------

    /**
     * Method description
     *
     *
     * @return
     */
    @Override
    public String getContextPath()
    {
      String header = getHeader(HEADER_CONTEXTPATH);

      if ((header == null) ||!isValidContextPath(header))
      {
        header = super.getContextPath();
      }

      return header;
    }

    /**
     * Method description
     *
     *
     * @return
     */
    @Override
    public String getPathInfo()
    {
      String pathInfo = super.getPathInfo();

      AssertUtil.assertIsNotEmpty(pathInfo);

      if (repository != null)
      {
        if (pathInfo.startsWith(HttpUtil.SEPARATOR_PATH))
        {
          pathInfo = pathInfo.substring(1);
        }

        pathInfo = pathInfo.substring(repository.getNamespace().length() + 1 + repository.getName().length());
      }

      return pathInfo;
    }

    /**
     * Method description
     *
     *
     * @return
     */
    @Override
    public String getServletPath()
    {
      String servletPath = super.getServletPath();

      if (repository != null)
      {
        if (!servletPath.endsWith(HttpUtil.SEPARATOR_PATH))
        {
          servletPath = servletPath.concat(HttpUtil.SEPARATOR_PATH);
        }

        servletPath = servletPath + repository.getNamespace() + "/" + repository.getName();
      }

      return servletPath;
    }

    /**
     * Method description
     *
     *
     * @param ctx
     *
     * @return
     */
    private boolean isValidContextPath(String ctx)
    {
      int length = ctx.length();

      boolean result = (length == 0)
                       || ((length > 1)
                         && ctx.startsWith(HttpUtil.SEPARATOR_PATH));

      if (!result)
      {
        logger.warn(
          "header {} contains a non valid context path, fallback to default",
          HEADER_CONTEXTPATH);
      }

      return result;
    }

    //~--- fields -------------------------------------------------------------

    /** Field description */
    private final Repository repository;
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private final SvnCollectionRenderer collectionRenderer;

  /** Field description */
  private final SvnRepositoryHandler handler;

  /** Field description */
  private final RepositoryProvider repositoryProvider;

  /** Field description */
  private final RepositoryRequestListenerUtil repositoryRequestListenerUtil;
}
