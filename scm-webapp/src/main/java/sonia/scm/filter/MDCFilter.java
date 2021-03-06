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



package sonia.scm.filter;

//~--- non-JDK imports --------------------------------------------------------

import com.google.common.annotations.VisibleForTesting;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import org.slf4j.MDC;

import sonia.scm.SCMContext;
import sonia.scm.security.DefaultKeyGenerator;
import sonia.scm.web.filter.HttpFilter;

//~--- JDK imports ------------------------------------------------------------

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import sonia.scm.Priority;

/**
 *
 * @author Sebastian Sdorra
 */
@Priority(Filters.PRIORITY_POST_AUTHENTICATION)
@WebElement(Filters.PATTERN_ALL)
public class MDCFilter extends HttpFilter
{
  private static final DefaultKeyGenerator TRANSACTION_KEY_GENERATOR = new DefaultKeyGenerator();

  @VisibleForTesting
  static final String MDC_CLIENT_HOST = "client_host";

  @VisibleForTesting
  static final String MDC_CLIENT_IP = "client_ip";

  @VisibleForTesting
  static final String MDC_REQUEST_URI = "request_uri";

  @VisibleForTesting
  static final String MDC_REQUEST_METHOD = "request_method";

  @VisibleForTesting
  static final String MDC_USERNAME = "username";

  @VisibleForTesting
  static final String MDC_TRANSACTION_ID = "transaction_id";

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param request
   * @param response
   * @param chain
   *
   * @throws IOException
   * @throws ServletException
   */
  @Override
  protected void doFilter(HttpServletRequest request,
    HttpServletResponse response, FilterChain chain)
    throws IOException, ServletException
  {
    MDC.put(MDC_USERNAME, getUsername());
    MDC.put(MDC_CLIENT_IP, request.getRemoteAddr());
    MDC.put(MDC_CLIENT_HOST, request.getRemoteHost());
    MDC.put(MDC_REQUEST_METHOD, request.getMethod());
    MDC.put(MDC_REQUEST_URI, request.getRequestURI());
    MDC.put(MDC_TRANSACTION_ID, TRANSACTION_KEY_GENERATOR.createKey());

    try
    {
      chain.doFilter(request, response);
    }
    finally
    {
      MDC.remove(MDC_USERNAME);
      MDC.remove(MDC_CLIENT_IP);
      MDC.remove(MDC_CLIENT_HOST);
      MDC.remove(MDC_REQUEST_METHOD);
      MDC.remove(MDC_REQUEST_URI);
      MDC.remove(MDC_TRANSACTION_ID);
    }
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  private String getUsername()
  {
    Subject subject = SecurityUtils.getSubject();
    String username;
    Object principal = subject.getPrincipal();

    if (principal == null)
    {
      username = SCMContext.USER_ANONYMOUS;
    }
    else
    {
      username = principal.toString();
    }

    return username;
  }
}
