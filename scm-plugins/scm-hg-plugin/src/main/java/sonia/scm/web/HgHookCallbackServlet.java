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

//~--- non-JDK imports --------------------------------------------------------

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.io.Closeables;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.NotFoundException;
import sonia.scm.repository.HgContext;
import sonia.scm.repository.HgHookManager;
import sonia.scm.repository.HgRepositoryHandler;
import sonia.scm.repository.RepositoryHookType;
import sonia.scm.repository.api.HgHookMessage;
import sonia.scm.repository.api.HgHookMessage.Severity;
import sonia.scm.repository.spi.HgHookContextProvider;
import sonia.scm.repository.spi.HookEventFacade;
import sonia.scm.security.BearerToken;
import sonia.scm.security.CipherUtil;
import sonia.scm.util.HttpUtil;
import sonia.scm.util.Util;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 */
@Singleton
public class HgHookCallbackServlet extends HttpServlet
{

  /** Field description */
  public static final String HGHOOK_POST_RECEIVE = "changegroup";

  /** Field description */
  public static final String HGHOOK_PRE_RECEIVE = "pretxnchangegroup";

  /** Field description */
  public static final String PARAM_REPOSITORYID = "repositoryId";

  /** Field description */
  private static final String PARAM_CHALLENGE = "challenge";

  /** Field description */
  private static final String PARAM_TOKEN = "token";

  /** Field description */
  private static final String PARAM_NODE = "node";

  /** Field description */
  private static final String PARAM_PING = "ping";

  /** Field description */
  private static final Pattern REGEX_URL =
    Pattern.compile("^/hook/hg/([^/]+)$");

  /** the logger for HgHookCallbackServlet */
  private static final Logger logger =
    LoggerFactory.getLogger(HgHookCallbackServlet.class);

  /** Field description */
  private static final long serialVersionUID = 3531596724828189353L;

  //~--- constructors ---------------------------------------------------------

  @Inject
  public HgHookCallbackServlet(HookEventFacade hookEventFacade,
                               HgRepositoryHandler handler, HgHookManager hookManager,
                               Provider<HgContext> contextProvider)
  {
    this.hookEventFacade = hookEventFacade;
    this.handler = handler;
    this.hookManager = hookManager;
    this.contextProvider = contextProvider;
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
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    String ping = request.getParameter(PARAM_PING);

    if (Util.isNotEmpty(ping) && Boolean.parseBoolean(ping))
    {
      response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
    else
    {
      response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    try {
      handlePostRequest(request, response);
    }  catch (IOException ex) {
      logger.warn("error in hook callback execution, sending internal server error", ex);
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private void handlePostRequest(HttpServletRequest request, HttpServletResponse response) throws IOException
  {
    String strippedURI = HttpUtil.getStrippedURI(request);
    Matcher m = REGEX_URL.matcher(strippedURI);

    if (m.matches())
    {
      String repositoryId = getRepositoryId(request);
      String type = m.group(1);
      String challenge = request.getParameter(PARAM_CHALLENGE);

      if (Util.isNotEmpty(challenge))
      {
        String node = request.getParameter(PARAM_NODE);

        if (Util.isNotEmpty(node))
        {
          String token = request.getParameter(PARAM_TOKEN);

          if (Util.isNotEmpty(token))
          {
            authenticate(token);
          }

          hookCallback(response, type, repositoryId, challenge, node);
        }
        else if (logger.isDebugEnabled())
        {
          logger.debug("node parameter not found");
        }
      }
      else if (logger.isDebugEnabled())
      {
        logger.debug("challenge parameter not found");
      }
    }
    else
    {
      if (logger.isDebugEnabled())
      {
        logger.debug("url does not match");
      }

      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    }
  }

  private void authenticate(String token)
  {
    try
    {
      token = CipherUtil.getInstance().decode(token);

      if (Util.isNotEmpty(token))
      {
        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken accessToken = createToken(token);

        //J-
        subject.login(accessToken);
      }
    }
    catch (Exception ex)
    {
      logger.error("could not authenticate user", ex);
    }
  }

  private AuthenticationToken createToken(String tokenString)
  {
    return BearerToken.valueOf(tokenString);
  }

  private void fireHook(HttpServletResponse response, String repositoryId, String node, RepositoryHookType type)
    throws IOException
  {
    HgHookContextProvider context = null;

    try
    {
      if (type == RepositoryHookType.PRE_RECEIVE)
      {
        contextProvider.get().setPending(true);
      }

      File repositoryDirectory = handler.getDirectory(repositoryId);
      context = new HgHookContextProvider(handler, repositoryDirectory, hookManager,
        node, type);

      hookEventFacade.handle(repositoryId).fireHookEvent(type, context);

      printMessages(response, context);
    }
    catch (NotFoundException ex)
    {
      logger.error(ex.getMessage());

      logger.trace("repository not found", ex);

      response.sendError(HttpServletResponse.SC_NOT_FOUND);
    }
    catch (Exception ex)
    {
      sendError(response, context, ex);
    }
  }

  private void hookCallback(HttpServletResponse response, String typeName, String repositoryId, String challenge, String node) throws IOException {
    if (hookManager.isAcceptAble(challenge))
    {
      RepositoryHookType type = null;

      if (HGHOOK_PRE_RECEIVE.equals(typeName))
      {
        type = RepositoryHookType.PRE_RECEIVE;
      }
      else if (HGHOOK_POST_RECEIVE.equals(typeName))
      {
        type = RepositoryHookType.POST_RECEIVE;
      }

      if (type != null)
      {
        fireHook(response, repositoryId, node, type);
      }
      else
      {
        if (logger.isWarnEnabled())
        {
          logger.warn("unknown hook type {}", typeName);
        }

        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      }
    }
    else
    {
      if (logger.isWarnEnabled())
      {
        logger.warn("hg hook challenge is not accept able");
      }

      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    }
  }

  /**
   * Method description
   *
   *
   * @param writer
   * @param msg
   */
  private void printMessage(PrintWriter writer, HgHookMessage msg)
  {
    writer.append('_');

    if (msg.getSeverity() == Severity.ERROR)
    {
      writer.append("e[SCM] Error: ");
    }
    else
    {
      writer.append("n[SCM] ");
    }

    writer.println(msg.getMessage());
  }

  /**
   * Method description
   *
   *
   * @param response
   * @param context
   *
   * @throws IOException
   */
  private void printMessages(HttpServletResponse response,
    HgHookContextProvider context)
    throws IOException
  {
    List<HgHookMessage> msgs = context.getHgMessageProvider().getMessages();

    if (Util.isNotEmpty(msgs))
    {
      PrintWriter writer = null;

      try
      {
        writer = response.getWriter();

        printMessages(writer, msgs);
      }
      finally
      {
        Closeables.close(writer, false);
      }
    }
  }

  /**
   * Method description
   *
   *
   * @param writer
   * @param msgs
   */
  private void printMessages(PrintWriter writer, List<HgHookMessage> msgs)
  {
    for (HgHookMessage msg : msgs)
    {
      printMessage(writer, msg);
    }
  }

  /**
   * Method description
   *
   *
   * @param response
   * @param context
   * @param ex
   *
   * @throws IOException
   */
  private void sendError(HttpServletResponse response,
    HgHookContextProvider context, Exception ex)
    throws IOException
  {
    logger.warn("hook ended with exception", ex);
    response.setStatus(HttpServletResponse.SC_CONFLICT);

    String msg = ex.getMessage();
    List<HgHookMessage> msgs = null;

    if (context != null)
    {
      msgs = context.getHgMessageProvider().getMessages();
    }

    if (!Strings.isNullOrEmpty(msg) || Util.isNotEmpty(msgs))
    {
      PrintWriter writer = null;

      try
      {
        writer = response.getWriter();

        if (Util.isNotEmpty(msgs))
        {
          printMessages(writer, msgs);
        }

        if (!Strings.isNullOrEmpty(msg))
        {
          printMessage(writer, new HgHookMessage(Severity.ERROR, msg));
        }
      }
      finally
      {
        Closeables.close(writer, true);
      }
    }
  }

  //~--- get methods ----------------------------------------------------------

  private String getRepositoryId(HttpServletRequest request)
  {
    String id = request.getParameter(PARAM_REPOSITORYID);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(id), "repository id not found in request");
    return id;
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private final Provider<HgContext> contextProvider;

  /** Field description */
  private final HgRepositoryHandler handler;

  /** Field description */
  private final HookEventFacade hookEventFacade;

  /** Field description */
  private final HgHookManager hookManager;
}
