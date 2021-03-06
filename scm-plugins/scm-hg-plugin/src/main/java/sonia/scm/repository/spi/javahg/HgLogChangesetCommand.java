/**
 * Copyright (c) 2010, Sebastian Sdorra
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


package sonia.scm.repository.spi.javahg;

import com.aragost.javahg.Repository;
import com.aragost.javahg.internals.HgInputStream;
import com.aragost.javahg.internals.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.Changeset;
import sonia.scm.repository.HgConfig;
import sonia.scm.repository.Modifications;

import java.io.IOException;
import java.util.List;

/**
 * @author Sebastian Sdorra
 */
public class HgLogChangesetCommand extends AbstractChangesetCommand {

  private static final Logger LOG = LoggerFactory.getLogger(HgLogChangesetCommand.class);

  private HgLogChangesetCommand(Repository repository, HgConfig config) {
    super(repository, config);
  }


  public static HgLogChangesetCommand on(Repository repository, HgConfig config) {
    return new HgLogChangesetCommand(repository, config);
  }


  public HgLogChangesetCommand branch(String branch) {
    cmdAppend("-b", branch);

    return this;
  }


  public List<Changeset> execute(String... files) {
    return readListFromStream(getHgInputStream(files, CHANGESET_EAGER_STYLE_PATH));
  }

  public Modifications extractModifications(String... files) {
    HgInputStream hgInputStream = getHgInputStream(files, CHANGESET_EAGER_STYLE_PATH);
    try {
      return readModificationsFromStream(hgInputStream);
    } finally {
      try {
        hgInputStream.close();
      } catch (IOException e) {
        LOG.error("Could not close HgInputStream", e);
      }
    }
  }

  HgInputStream getHgInputStream(String[] files, String changesetStylePath) {
    cmdAppend("--style", changesetStylePath);
    return launchStream(files);
  }

  public HgLogChangesetCommand limit(int limit) {
    cmdAppend("-l", limit);

    return this;
  }


  public List<Integer> loadRevisions(String... files) {
    return loadRevisionsFromStream(getHgInputStream(files, CHANGESET_LAZY_STYLE_PATH));
  }

  public HgLogChangesetCommand rev(String... rev) {
    cmdAppend("-r", rev);

    return this;
  }

  public Changeset single(String... files) {
    return Utils.single(execute(files));
  }

  public int singleRevision(String... files) {
    Integer rev = Utils.single(loadRevisions(files));

    if (rev == null) {
      rev = -1;
    }

    return rev;
  }

  @Override
  public String getCommandName() {
    return "log";
  }
}
