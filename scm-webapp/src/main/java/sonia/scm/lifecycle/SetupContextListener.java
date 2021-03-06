package sonia.scm.lifecycle;

import com.google.common.annotations.VisibleForTesting;
import org.apache.shiro.authc.credential.PasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.SCMContext;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.plugin.Extension;
import sonia.scm.security.PermissionAssigner;
import sonia.scm.security.PermissionDescriptor;
import sonia.scm.user.User;
import sonia.scm.user.UserManager;
import sonia.scm.web.security.AdministrationContext;
import sonia.scm.web.security.PrivilegedAction;

import javax.inject.Inject;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.Collections;

@Extension
public class SetupContextListener implements ServletContextListener {

  private static final Logger LOG = LoggerFactory.getLogger(SetupContextListener.class);

  private final AdministrationContext administrationContext;

  @Inject
  public SetupContextListener(AdministrationContext administrationContext) {
    this.administrationContext = administrationContext;
  }

  @Override
  public void contextInitialized(ServletContextEvent sce) {
    if (Boolean.getBoolean("sonia.scm.skipAdminCreation")) {
      LOG.info("found skipAdminCreation flag; skipping creation of scmadmin");
    } else {
      administrationContext.runAsAdmin(SetupAction.class);
    }
  }

  @Override
  public void contextDestroyed(ServletContextEvent sce) {}

  @VisibleForTesting
  static class SetupAction implements PrivilegedAction {

    private final UserManager userManager;
    private final PasswordService passwordService;
    private final PermissionAssigner permissionAssigner;
    private final ScmConfiguration scmConfiguration;

    @Inject
    public SetupAction(UserManager userManager, PasswordService passwordService, PermissionAssigner permissionAssigner, ScmConfiguration scmConfiguration) {
      this.userManager = userManager;
      this.passwordService = passwordService;
      this.permissionAssigner = permissionAssigner;
      this.scmConfiguration = scmConfiguration;
    }

    @Override
    public void run() {
      if (shouldCreateAdminAccount()) {
        createAdminAccount();
      }
      if (anonymousUserRequiredButNotExists()) {
        userManager.create(SCMContext.ANONYMOUS);
      }
    }

    private boolean anonymousUserRequiredButNotExists() {
      return scmConfiguration.isAnonymousAccessEnabled() && !userManager.contains(SCMContext.USER_ANONYMOUS);
    }

    private boolean shouldCreateAdminAccount() {
      return userManager.getAll().isEmpty() || onlyAnonymousUserExists();
    }

    private boolean onlyAnonymousUserExists() {
      return userManager.getAll().size() == 1 && userManager.contains(SCMContext.USER_ANONYMOUS);
    }

    private void createAdminAccount() {
      User scmadmin = new User("scmadmin", "SCM Administrator", "scm-admin@scm-manager.org");
      String password = passwordService.encryptPassword("scmadmin");
      scmadmin.setPassword(password);
      userManager.create(scmadmin);

      PermissionDescriptor descriptor = new PermissionDescriptor("*");
      permissionAssigner.setPermissionsForUser("scmadmin", Collections.singleton(descriptor));
    }
  }
}
