/**
 * Copyright (c) 2014, Sebastian Sdorra All rights reserved.
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



package sonia.scm.web;

//~--- non-JDK imports --------------------------------------------------------

import sonia.scm.plugin.Extension;
import sonia.scm.security.BearerToken;

//~--- JDK imports ------------------------------------------------------------

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import sonia.scm.util.HttpUtil;

/**
 * Creates an {@link BearerToken} from the {@link HttpUtil#COOKIE_BEARER_AUTHENTICATION}
 * cookie.
 *
 * @author Sebastian Sdorra
 * @since 2.0.0
 */
@Extension
public class CookieBearerWebTokenGenerator implements WebTokenGenerator
{

  /**
   * Creates an {@link BearerToken} from the {@link HttpUtil#COOKIE_BEARER_AUTHENTICATION}
   * cookie.
   *
   * @param request http servlet request
   *
   * @return {@link BearerToken} or {@code null}
   */
  @Override
  public BearerToken createToken(HttpServletRequest request)
  {
    BearerToken token = null;
    Cookie[] cookies = request.getCookies();

    if (cookies != null)
    {
      for (Cookie cookie : cookies)
      {
        if (HttpUtil.COOKIE_BEARER_AUTHENTICATION.equals(cookie.getName()))
        {
          String sessionId = HttpUtil.getHeader(request, HttpUtil.HEADER_SCM_SESSION, null);
          token = BearerToken.create(sessionId, cookie.getValue());

          break;
        }
      }
    }

    return token;
  }
}
