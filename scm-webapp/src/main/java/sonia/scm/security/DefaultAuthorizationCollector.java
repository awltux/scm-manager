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



package sonia.scm.security;

//~--- non-JDK imports --------------------------------------------------------

import com.github.legman.Subscribe;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSet.Builder;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.cache.Cache;
import sonia.scm.cache.CacheManager;
import sonia.scm.group.GroupCollector;
import sonia.scm.group.GroupPermissions;
import sonia.scm.plugin.Extension;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryDAO;
import sonia.scm.repository.RepositoryPermission;
import sonia.scm.user.User;
import sonia.scm.user.UserPermissions;
import sonia.scm.util.Util;

import java.util.Collection;
import java.util.Set;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 */
@Singleton
@Extension
public class DefaultAuthorizationCollector implements AuthorizationCollector
{

  /** Field description */
  private static final String CACHE_NAME = "sonia.cache.authorizing";

  /**
   * the logger for DefaultAuthorizationCollector
   */
  private static final Logger logger =
    LoggerFactory.getLogger(DefaultAuthorizationCollector.class);

  //~--- constructors ---------------------------------------------------------

  /**
   * Constructs ...
   * @param cacheManager
   * @param repositoryDAO
   * @param securitySystem
   * @param repositoryPermissionProvider
   * @param groupCollector
   */
  @Inject
  public DefaultAuthorizationCollector(CacheManager cacheManager,
                                       RepositoryDAO repositoryDAO, SecuritySystem securitySystem, RepositoryPermissionProvider repositoryPermissionProvider, GroupCollector groupCollector)
  {
    this.cache = cacheManager.getCache(CACHE_NAME);
    this.repositoryDAO = repositoryDAO;
    this.securitySystem = securitySystem;
    this.repositoryPermissionProvider = repositoryPermissionProvider;
    this.groupCollector = groupCollector;
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  @VisibleForTesting
  AuthorizationInfo collect()
  {
    AuthorizationInfo authorizationInfo;
    Subject subject = SecurityUtils.getSubject();

    if (subject.hasRole(Role.USER))
    {
      authorizationInfo = collect(subject.getPrincipals());
    }
    else
    {
      authorizationInfo = new SimpleAuthorizationInfo();
    }

    return authorizationInfo;
  }

  /**
   * Method description
   *
   * @param principals
   *
   * @return
   */
  @Override
  public AuthorizationInfo collect(PrincipalCollection principals)
  {
    Preconditions.checkNotNull(principals, "principals parameter is required");

    User user = principals.oneByType(User.class);

    Preconditions.checkNotNull(user, "no user found in principal collection");

    Set<String> groups = groupCollector.collect(user.getName());

    CacheKey cacheKey = new CacheKey(user.getId(), groups);

    AuthorizationInfo info = cache.get(cacheKey);

    if (info == null)
    {
      logger.trace("collect AuthorizationInfo for user {}", user.getName());
      info = createAuthorizationInfo(user, groups);
      cache.put(cacheKey, info);
    }
    else if (logger.isTraceEnabled())
    {
      logger.trace("retrieve AuthorizationInfo for user {} from cache", user.getName());
    }

    return info;
  }

  private void collectGlobalPermissions(Builder<String> builder,
    final User user, final Set<String> groups)
  {
    Collection<AssignedPermission> globalPermissions =
      securitySystem.getPermissions((AssignedPermission input) -> isUserPermitted(user, groups, input));

    for (AssignedPermission gp : globalPermissions)
    {
      String permission = gp.getPermission().getValue();

      logger.trace("add permission {} for user {}", permission, user.getName());
      builder.add(permission);
    }
  }

  private void collectRepositoryPermissions(Builder<String> builder, User user,
    Set<String> groups)
  {
    for (Repository repository : repositoryDAO.getAll())
    {
      collectRepositoryPermissions(builder, repository, user, groups);
    }
  }

  private void collectRepositoryPermissions(Builder<String> builder,
    Repository repository, User user, Set<String> groups)
  {
    Collection<RepositoryPermission> repositoryPermissions = repository.getPermissions();

    if (Util.isNotEmpty(repositoryPermissions))
    {
      boolean hasPermission = false;
      for (RepositoryPermission permission : repositoryPermissions)
      {
        hasPermission = isUserPermitted(user, groups, permission);
        if (hasPermission) {
          addRepositoryPermission(builder, repository, user, permission);
        }
      }

      if (!hasPermission && logger.isTraceEnabled())
      {
        logger.trace("no permission for user {} defined at repository {}", user.getName(), repository.getName());
      }
    }
    else if (logger.isTraceEnabled())
    {
      logger.trace("repository {} has no permission entries",
        repository.getName());
    }
  }

  private void addRepositoryPermission(Builder<String> builder, Repository repository, User user, RepositoryPermission permission) {
    Collection<String> verbs = getVerbs(permission);
    if (!verbs.isEmpty())
    {
      String perm = "repository:" + String.join(",", verbs) + ":" + repository.getId();
      if (logger.isTraceEnabled())
      {
        logger.trace("add repository permission {} for user {} at repository {}",
          perm, user.getName(), repository.getName());
      }

      builder.add(perm);
    }
  }

  private Collection<String> getVerbs(RepositoryPermission permission) {
    return permission.getRole() == null? permission.getVerbs(): getVerbsForRole(permission.getRole());
  }

  private Collection<String> getVerbsForRole(String roleName) {
    return repositoryPermissionProvider.availableRoles()
      .stream()
      .filter(role -> roleName.equals(role.getName()))
      .findFirst()
      .orElseThrow(() -> new IllegalStateException("unknown role: " + roleName))
      .getVerbs();
  }

  private AuthorizationInfo createAuthorizationInfo(User user, Set<String> groups) {
    Builder<String> builder = ImmutableSet.builder();

    collectGlobalPermissions(builder, user, groups);
    collectRepositoryPermissions(builder, user, groups);
    builder.add(canReadOwnUser(user));
    if (!Authentications.isSubjectAnonymous(user.getName())) {
      builder.add(getUserAutocompletePermission());
      builder.add(getGroupAutocompletePermission());
      builder.add(getChangeOwnPasswordPermission(user));
    }

    SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(ImmutableSet.of(Role.USER));
    info.addStringPermissions(builder.build());

    return info;
  }

  private String getGroupAutocompletePermission() {
    return GroupPermissions.autocomplete().asShiroString();
  }

  private String getChangeOwnPasswordPermission(User user) {
    return UserPermissions.changePassword(user).asShiroString();
  }

  private String getUserAutocompletePermission() {
    return UserPermissions.autocomplete().asShiroString();
  }

  private String canReadOwnUser(User user) {
    return UserPermissions.read(user.getName()).asShiroString();
  }

  //~--- get methods ----------------------------------------------------------

  private boolean isUserPermitted(User user, Set<String> groups,
    PermissionObject perm)
  {
    //J-
    return (perm.isGroupPermission() && groups.contains(perm.getName()))
      || ((!perm.isGroupPermission()) && user.getName().equals(perm.getName()));
    //J+
  }

  @Subscribe
  public void invalidateCache(AuthorizationChangedEvent event) {
    if (event.isEveryUserAffected()) {
      invalidateUserCache(event.getNameOfAffectedUser());
    } else {
      invalidateCache();
    }
  }

  private void invalidateUserCache(final String username) {
    logger.info("invalidate cache for user {}, because of a received authorization event", username);
    cache.removeAll((CacheKey item) -> username.equalsIgnoreCase(item.username));
  }

  private void invalidateCache() {
    logger.info("invalidate cache, because of a received authorization event");
    cache.clear();
  }

  //~--- inner classes --------------------------------------------------------

  /**
   * Cache key.
   */
  private static class CacheKey
  {
    private CacheKey(String username, Set<String> groupnames)
    {
      this.username = username;
      this.groupnames = groupnames;
    }

    //~--- methods ------------------------------------------------------------

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

      final CacheKey other = (CacheKey) obj;

      return Objects.equal(username, other.username)
        && Objects.equal(groupnames, other.groupnames);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
      return Objects.hashCode(username, groupnames);
    }

    //~--- fields -------------------------------------------------------------

    /** group names */
    private final Set<String> groupnames;

    /** username */
    private final String username;
  }

  //~--- fields ---------------------------------------------------------------

  /** authorization cache */
  private final Cache<CacheKey, AuthorizationInfo> cache;

  /** repository dao */
  private final RepositoryDAO repositoryDAO;

  /** security system */
  private final SecuritySystem securitySystem;

  private final RepositoryPermissionProvider repositoryPermissionProvider;
  private final GroupCollector groupCollector;
}
