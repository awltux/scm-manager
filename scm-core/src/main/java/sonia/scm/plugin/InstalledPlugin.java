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



package sonia.scm.plugin;

//~--- JDK imports ------------------------------------------------------------

import java.nio.file.Path;

/**
 * Wrapper for a {@link InstalledPluginDescriptor}. The wrapper holds the directory,
 * {@link ClassLoader} and {@link WebResourceLoader} of a plugin.
 *
 * @author Sebastian Sdorra
 * @since 2.0.0
 */
public final class InstalledPlugin implements Plugin
{

  public static final String UNINSTALL_MARKER_FILENAME = "uninstall";

  /**
   * Constructs a new plugin wrapper.
   *  @param descriptor wrapped plugin
   * @param classLoader plugin class loader
   * @param webResourceLoader web resource loader
   * @param directory plugin directory
   * @param core marked as core or not
   */
  public InstalledPlugin(InstalledPluginDescriptor descriptor, ClassLoader classLoader,
                         WebResourceLoader webResourceLoader, Path directory, boolean core)
  {
    this.descriptor = descriptor;
    this.classLoader = classLoader;
    this.webResourceLoader = webResourceLoader;
    this.directory = directory;
    this.core = core;
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Returns plugin class loader.
   *
   *
   * @return plugin class loader
   */
  public ClassLoader getClassLoader()
  {
    return classLoader;
  }

  /**
   * Returns plugin directory.
   *
   *
   * @return plugin directory
   */
  public Path getDirectory()
  {
    return directory;
  }

  /**
   * Returns the id of the plugin.
   *
   *
   * @return id of plugin
   */
  public String getId()
  {
    return descriptor.getInformation().getId();
  }

  /**
   * Returns the plugin descriptor.
   *
   *
   * @return plugin descriptor
   */
  @Override
  public InstalledPluginDescriptor getDescriptor()
  {
    return descriptor;
  }

  /**
   * Returns the {@link WebResourceLoader} for this plugin.
   *
   *
   * @return web resource loader
   */
  public WebResourceLoader getWebResourceLoader()
  {
    return webResourceLoader;
  }

  public boolean isCore() {
    return core;
  }

  public boolean isMarkedForUninstall() {
    return markedForUninstall;
  }

  public void setMarkedForUninstall(boolean markedForUninstall) {
    this.markedForUninstall = markedForUninstall;
  }

  public boolean isUninstallable() {
    return uninstallable;
  }

  public void setUninstallable(boolean uninstallable) {
    this.uninstallable = uninstallable;
  }

//~--- fields ---------------------------------------------------------------

  /** plugin class loader */
  private final ClassLoader classLoader;

  /** plugin directory */
  private final Path directory;

  /** plugin */
  private final InstalledPluginDescriptor descriptor;

  /** plugin web resource loader */
  private final WebResourceLoader webResourceLoader;

  private final boolean core;

  private boolean markedForUninstall = false;
  private boolean uninstallable = false;
}
