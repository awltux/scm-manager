/**
 * Copyright (c) 2014, Sebastian Sdorra
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
package sonia.scm.security;

import com.google.common.annotations.VisibleForTesting;

import java.util.UUID;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.servlet.http.HttpServletRequest;

import com.google.inject.OutOfScopeException;
import com.google.inject.ProvisionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.plugin.Extension;
import sonia.scm.util.HttpUtil;

/**
 * Xsrf access token enricher will add an xsrf custom field to the access token. The enricher will only
 * add the xsrf field, if the authentication request is issued from the web interface and xsrf protection is
 * enabled. The xsrf field will be validated on every request by the {@link XsrfAccessTokenValidator}. Xsrf protection
 * can be disabled with {@link ScmConfiguration#setEnabledXsrfProtection(boolean)}.
 *
 * @author Sebastian Sdorra
 * @see <a href="https://goo.gl/s67xO3">Issue 793</a>
 * @since 2.0.0
 */
@Extension
public class XsrfAccessTokenEnricher implements AccessTokenEnricher {

  /**
   * the logger for XsrfAccessTokenEnricher
   */
  private static final Logger LOG = LoggerFactory.getLogger(XsrfAccessTokenEnricher.class);

  private final ScmConfiguration configuration;
  private final Provider<HttpServletRequest> requestProvider;

  /**
   * Constructs a new instance.
   *
   * @param configuration   scm main configuration
   * @param requestProvider http request provider
   */
  @Inject
  public XsrfAccessTokenEnricher(ScmConfiguration configuration, Provider<HttpServletRequest> requestProvider) {
    this.configuration = configuration;
    this.requestProvider = requestProvider;
  }

  @Override
  public void enrich(AccessTokenBuilder builder) {
    if (configuration.isEnabledXsrfProtection()) {
      if (isEnrichable()) {
        builder.custom(Xsrf.TOKEN_KEY, createToken());
      }
    } else {
      LOG.trace("xsrf is disabled, skip xsrf enrichment");
    }
  }

  private boolean isEnrichable() {
    try {
      HttpServletRequest request = requestProvider.get();
      if (HttpUtil.isWUIRequest(request)) {
        LOG.debug("received wui token claim, enrich jwt with xsrf key");
        return true;
      } else {
        LOG.trace("skip xsrf enrichment, because jwt session is started from a non wui client");
        return false;
      }
    } catch (ProvisionException ex) {
      if (ex.getCause() instanceof OutOfScopeException) {
        LOG.trace("skip xsrf enrichment, because no request scope is available");
        return false;
      } else {
        throw ex;
      }
    }
  }

  @VisibleForTesting
  String createToken() {
    // TODO create interface and use a better method
    return UUID.randomUUID().toString();
  }

}
