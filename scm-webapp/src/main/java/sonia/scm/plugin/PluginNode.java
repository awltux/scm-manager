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

//~--- non-JDK imports --------------------------------------------------------

import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

//~--- JDK imports ------------------------------------------------------------

import java.util.List;

/**
 *
 * @author Sebastian Sdorra
 */
public final class PluginNode
{

  /**
   * Constructs ...
   *
   *
   * @param plugin
   */
  public PluginNode(ExplodedSmp plugin)
  {
    this.plugin = plugin;
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param node
   */
  public void addChild(PluginNode node)
  {
    this.children.add(node);
    node.addParent(this);
  }

  /**
   * Method description
   *
   *
   * @param node
   */
  private void addParent(PluginNode node)
  {
    this.parents.add(node);
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param id
   *
   * @return
   */
  public PluginNode getChild(final String id)
  {
    return Iterables.find(children, new Predicate<PluginNode>()
    {

      @Override
      public boolean apply(PluginNode node)
      {
        return node.getId().equals(id);
      }
    });
  }

  /**
   * Method description
   *
   *
   * @return
   */
  public List<PluginNode> getChildren()
  {
    return children;
  }

  /**
   * Method description
   *
   *
   * @return
   */
  public String getId()
  {
    return plugin.getPlugin().getInformation().getName(false);
  }

  /**
   * Method description
   *
   *
   * @return
   */
  public List<PluginNode> getParents()
  {
    return parents;
  }

  /**
   * Method description
   *
   *
   * @return
   */
  public ExplodedSmp getPlugin()
  {
    return plugin;
  }

  /**
   * Method description
   *
   *
   * @return
   */
  public InstalledPlugin getWrapper()
  {
    return wrapper;
  }

  //~--- set methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param wrapper
   */
  public void setWrapper(InstalledPlugin wrapper)
  {
    this.wrapper = wrapper;
  }

  @Override
  public int hashCode() {
    return getId().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return obj instanceof PluginNode
      && ((PluginNode) obj).getId().equals(this.getId());
  }

  @Override
  public String toString() {
    return plugin.getPath().toString() + " -> " + children;
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private final List<PluginNode> parents = Lists.newArrayList();

  /** Field description */
  private final List<PluginNode> children = Lists.newArrayList();

  /** Field description */
  private final ExplodedSmp plugin;

  /** Field description */
  private InstalledPlugin wrapper;
}
