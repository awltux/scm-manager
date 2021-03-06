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



package sonia.scm.plugin;

//~--- non-JDK imports --------------------------------------------------------

import com.google.common.base.Stopwatch;
import com.google.inject.Binder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Sebastian Sdorra
 */
@SuppressWarnings("unchecked")
public class DefaultExtensionProcessor implements ExtensionProcessor
{

  /**
   * the logger for DefaultExtensionProcessor
   */
  private static final Logger logger =
    LoggerFactory.getLogger(DefaultExtensionProcessor.class);

  //~--- constructors ---------------------------------------------------------

  /**
   * Constructs ...
   *
   *
   * @param collector
   */
  public DefaultExtensionProcessor(ExtensionCollector collector)
  {
    this.collector = collector;
  }

  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   *
   * @param extensionPoint
   *
   * @return
   */
  @Override
  public Iterable<Class> byExtensionPoint(Class extensionPoint)
  {
    return collector.byExtensionPoint(extensionPoint);
  }

  /**
   * Method description
   *
   *
   * @param extensionPoint
   *
   * @return
   */
  @Override
  public Class oneByExtensionPoint(Class extensionPoint)
  {
    return collector.oneByExtensionPoint(extensionPoint);
  }

  /**
   * Method description
   *
   *
   * @param binder
   */
  @Override
  public void processAutoBindExtensions(Binder binder)
  {
    logger.info("start processing extensions");

    Stopwatch sw = Stopwatch.createStarted();

    new ExtensionBinder(binder).bind(collector);
    logger.info("bound extensions in {}", sw.stop());
  }

  //~--- get methods ----------------------------------------------------------

  /**
   * Method description
   *
   *
   * @return
   */
  @Override
  public Iterable<WebElementDescriptor> getWebElements()
  {
    return collector.getWebElements();
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private final ExtensionCollector collector;
}
