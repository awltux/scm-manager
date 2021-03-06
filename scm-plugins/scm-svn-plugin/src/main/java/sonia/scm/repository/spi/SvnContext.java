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


package sonia.scm.repository.spi;

//~--- non-JDK imports --------------------------------------------------------

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.io.SVNRepository;
import org.tmatesoft.svn.core.io.SVNRepositoryFactory;

import sonia.scm.repository.Repository;
import sonia.scm.repository.SvnUtil;

//~--- JDK imports ------------------------------------------------------------

import java.io.Closeable;
import java.io.File;

/**
 *
 * @author Sebastian Sdorra
 */
public class SvnContext implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(SvnContext.class);

  private final Repository repository;
  private final File directory;

  private SVNRepository svnRepository;

  public SvnContext(Repository repository, File directory) {
    this.repository = repository;
    this.directory = directory;
  }

  public Repository getRepository() {
    return repository;
  }

  public File getDirectory() {
    return directory;
  }

  public SVNURL createUrl() throws SVNException {
    return SVNURL.fromFile(directory);
  }

  public SVNRepository open() throws SVNException {
    if (svnRepository == null) {
      LOG.trace("open svn repository {}", directory);
      svnRepository = SVNRepositoryFactory.create(createUrl());
    }

    return svnRepository;
  }

  @Override
  public void close() {
    LOG.trace("close svn repository {}", directory);
    SvnUtil.closeSession(svnRepository);
  }

}
