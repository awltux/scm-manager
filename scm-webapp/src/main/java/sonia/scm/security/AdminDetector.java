/**
 * Copyright (c) 2014, Sebastian Sdorra
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
package sonia.scm.security;

import com.google.inject.Inject;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Properties;
import java.util.Set;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.user.User;
import sonia.scm.util.Util;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;


/**
 * Detects administrator from configuration.
 *
 * @author Sebastian Sdorra
 * @since 1.52
 */
public class AdminDetector {

  private static final String scmPropertiesfilename = "/scm.properties";
  private static final Properties scmProperties;

  /**
   * the logger for AdminDetector
   */
  private static final Logger LOG = LoggerFactory.getLogger(AdminDetector.class);

  private final ScmConfiguration configuration;

 static{
    InputStream is = null;
    scmProperties = new Properties();
    try {
      is = AdminDetector.class.getResourceAsStream(scmPropertiesfilename);
      scmProperties.load(is);
    }
    catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    catch (IOException e) {
      e.printStackTrace();
    }
  }


  /**
   * Constructs admin detector.
   * 
   * @param configuration scm-manager main configuration
   */
  @Inject
  public AdminDetector(ScmConfiguration configuration) {
    this.configuration = configuration;
  }
  
  /**
   * Checks is the authenticated user is marked as administrator by {@link ScmConfiguration}.
   * 
   * @param user authenticated user
   * @param groups groups of authenticated user
   */
  public boolean checkForAuthenticatedAdmin(User user, Set<String> groups) {
    boolean adminFlagCameFromSSP = false;
    boolean isCurrentlyAdmin = user.isAdmin();
    // Default to no change
    boolean isAdmin = isCurrentlyAdmin;
    try {
      // Check SSP first, but only for ldap/activedirectory users
      if ( user.getType() == "ldap" || user.getType() == "activedirectory" ) {
        isAdmin = isAdminBySelfService(user);
        adminFlagCameFromSSP = true;
        if (isCurrentlyAdmin != isAdmin) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("CMRE SSP admin state changed for user {}. isAdmin={}", user.getName(), isAdmin);
          }
        } else {
          if (LOG.isDebugEnabled()) {
            LOG.debug("CMRE SSP admin state already synced with user {}. isAdmin={}", user.getName(), isAdmin);
          }
        }
      } else {
        throw new Exception("Only checks ldap users: type=" + user.getType() );
      }
    } catch(Exception e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("CMRE SSP admin check skipped: {}", e.toString());
      }
      if (!isCurrentlyAdmin) {
        // If SSP fails, fallback on SCM config
        isAdmin = isAdminByConfiguration(user, groups);
        if ( isAdmin ) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("user {} is marked as admin by configuration", user.getName());
          }
        }
      }
      else if (LOG.isDebugEnabled()) {
        LOG.debug("authenticator {} marked user {} as admin", user.getType(), user.getName());
      }
    }
    user.setAdmin(isAdmin);
    return adminFlagCameFromSSP;
  }
  
  
  private boolean isAdminBySelfService(User user) throws Exception {
    URL url = new URL(configuration.getBaseUrl());
    // Path is of the form "/scm"
    String projectId = url.getPath().split("/")[1];
    String sspUrl = scmProperties.getProperty("cmre.scm.url");
    String input = "{\"userId\":\"" + user.getName() + "\",\"projectId\":\"" + projectId + "\"}";

    Client client = Client.create();
    client.setReadTimeout(1000);
    client.setConnectTimeout(1000);
    WebResource webResource = client.resource(sspUrl);
    ClientResponse response = webResource.type("application/json")
       .post(ClientResponse.class, input);

    // SSP cannot decide if user and project are valid, so ignore.
    if (response.getStatus() != 200)
      throw new RuntimeException("CMRE SSP: Cannot resolve user '" + user.getName() + "' and project '" + projectId + "'");

    String booleanString = response.getEntity(String.class);
    // The booleanString should be either a 'true' or 'false' string
    return Boolean.parseBoolean(booleanString);
  }
  
  private boolean isAdminByConfiguration(User user, Collection<String> groups) {
    boolean result = false;
    
    Set<String> adminUsers = configuration.getAdminUsers();
    if (adminUsers != null) {
      result = adminUsers.contains(user.getName());
    }

    if (!result) {
      Set<String> adminGroups = configuration.getAdminGroups();

      if (adminGroups != null) {
        result = Util.containsOne(adminGroups, groups);
      }
    }

    return result;
  }
  
}
