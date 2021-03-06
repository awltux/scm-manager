
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

import com.google.common.io.Files;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import sonia.scm.repository.Changeset;
import sonia.scm.repository.ChangesetPagingResult;
import sonia.scm.repository.GitRepositoryConfig;
import sonia.scm.repository.Modifications;

import java.io.File;
import java.io.IOException;

import static java.nio.charset.Charset.defaultCharset;
import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link GitLogCommand}.
 *
 * @author Sebastian Sdorra
 */
@RunWith(MockitoJUnitRunner.class)
public class GitLogCommandTest extends AbstractGitCommandTestBase
{
  @Mock
  LogCommandRequest request;

  /**
   * Tests log command with the usage of a default branch.
   */
  @Test
  public void testGetDefaultBranch() {
    // without default branch, the repository head should be used
    ChangesetPagingResult result = createCommand().getChangesets(new LogCommandRequest());

    assertNotNull(result);
    assertEquals(4, result.getTotal());
    assertEquals("fcd0ef1831e4002ac43ea539f4094334c79ea9ec", result.getChangesets().get(0).getId());
    assertEquals("86a6645eceefe8b9a247db5eb16e3d89a7e6e6d1", result.getChangesets().get(1).getId());
    assertEquals("592d797cd36432e591416e8b2b98154f4f163411", result.getChangesets().get(2).getId());
    assertEquals("435df2f061add3589cb326cc64be9b9c3897ceca", result.getChangesets().get(3).getId());
    assertEquals("master", result.getBranchName());
    assertTrue(result.getChangesets().stream().allMatch(r -> r.getBranches().isEmpty()));

    // set default branch and fetch again
    createContext().setConfig(new GitRepositoryConfig("test-branch"));

    result = createCommand().getChangesets(new LogCommandRequest());

    assertNotNull(result);
    assertEquals("test-branch", result.getBranchName());
    assertEquals(3, result.getTotal());
    assertEquals("3f76a12f08a6ba0dc988c68b7f0b2cd190efc3c4", result.getChangesets().get(0).getId());
    assertEquals("592d797cd36432e591416e8b2b98154f4f163411", result.getChangesets().get(1).getId());
    assertEquals("435df2f061add3589cb326cc64be9b9c3897ceca", result.getChangesets().get(2).getId());
    assertTrue(result.getChangesets().stream().allMatch(r -> r.getBranches().isEmpty()));
  }

  @Test
  public void testGetAll()
  {
    ChangesetPagingResult result =
      createCommand().getChangesets(new LogCommandRequest());

    assertNotNull(result);
    assertEquals(4, result.getTotal());
    assertEquals(4, result.getChangesets().size());
  }

  @Test
  public void testGetAllByPath()
  {
    LogCommandRequest request = new LogCommandRequest();

    request.setPath("a.txt");

    ChangesetPagingResult result = createCommand().getChangesets(request);

    assertNotNull(result);
    assertEquals(2, result.getTotal());
    assertEquals(2, result.getChangesets().size());
    assertEquals("fcd0ef1831e4002ac43ea539f4094334c79ea9ec", result.getChangesets().get(0).getId());
    assertEquals("435df2f061add3589cb326cc64be9b9c3897ceca", result.getChangesets().get(1).getId());
  }

  @Test
  public void testGetAllWithLimit()
  {
    LogCommandRequest request = new LogCommandRequest();

    request.setPagingLimit(2);

    ChangesetPagingResult result = createCommand().getChangesets(request);

    assertNotNull(result);
    assertEquals(4, result.getTotal());
    assertEquals(2, result.getChangesets().size());

    Changeset c1 = result.getChangesets().get(0);

    assertNotNull(c1);
    assertEquals("fcd0ef1831e4002ac43ea539f4094334c79ea9ec", c1.getId());

    Changeset c2 = result.getChangesets().get(1);

    assertNotNull(c2);
    assertEquals("86a6645eceefe8b9a247db5eb16e3d89a7e6e6d1", c2.getId());
  }

  @Test
  public void testGetAllWithPaging()
  {
    LogCommandRequest request = new LogCommandRequest();

    request.setPagingStart(1);
    request.setPagingLimit(2);

    ChangesetPagingResult result = createCommand().getChangesets(request);

    assertNotNull(result);
    assertEquals(4, result.getTotal());
    assertEquals(2, result.getChangesets().size());

    Changeset c1 = result.getChangesets().get(0);

    assertNotNull(c1);
    assertEquals("86a6645eceefe8b9a247db5eb16e3d89a7e6e6d1", c1.getId());

    Changeset c2 = result.getChangesets().get(1);

    assertNotNull(c2);
    assertEquals("592d797cd36432e591416e8b2b98154f4f163411", c2.getId());
  }

  @Test
  public void testGetCommit()
  {
    GitLogCommand command = createCommand();
    Changeset c = command.getChangeset("435df2f061add3589cb3", null);

    assertNotNull(c);
    String revision = "435df2f061add3589cb326cc64be9b9c3897ceca";
    assertEquals(revision, c.getId());
    assertEquals("added a and b files", c.getDescription());
    checkDate(c.getDate());
    assertEquals("Douglas Adams", c.getAuthor().getName());
    assertEquals("douglas.adams@hitchhiker.com", c.getAuthor().getMail());
    assertEquals("added a and b files", c.getDescription());

    GitModificationsCommand gitModificationsCommand = new GitModificationsCommand(createContext(), repository);
    Modifications modifications = gitModificationsCommand.getModifications(revision);

    assertNotNull(modifications);
    assertTrue("modified list should be empty", modifications.getModified().isEmpty());
    assertTrue("removed list should be empty", modifications.getRemoved().isEmpty());
    assertFalse("added list should not be empty", modifications.getAdded().isEmpty());
    assertEquals(2, modifications.getAdded().size());
    assertThat(modifications.getAdded(), contains("a.txt", "b.txt"));
  }

  @Test
  public void commitShouldContainBranchIfLogCommandRequestHasBranch()
  {
    when(request.getBranch()).thenReturn("master");
    GitLogCommand command = createCommand();
    Changeset c = command.getChangeset("435df2f061add3589cb3", request);

    Assertions.assertThat(c.getBranches()).containsOnly("master");
  }

  @Test
  public void shouldNotReturnCommitFromDifferentBranch() {
    when(request.getBranch()).thenReturn("master");
    Changeset changeset = createCommand().getChangeset("3f76a12f08a6ba0dc988c68b7f0b2cd190efc3c4", request);
    Assertions.assertThat(changeset).isNull();
  }

  @Test
  public void testGetRange()
  {
    LogCommandRequest request = new LogCommandRequest();

    request.setStartChangeset("592d797cd36432e59141");
    request.setEndChangeset("435df2f061add3589cb3");

    ChangesetPagingResult result = createCommand().getChangesets(request);

    assertNotNull(result);
    assertEquals(2, result.getTotal());
    assertEquals(2, result.getChangesets().size());

    Changeset c1 = result.getChangesets().get(0);
    Changeset c2 = result.getChangesets().get(1);

    assertNotNull(c1);
    assertEquals("592d797cd36432e591416e8b2b98154f4f163411", c1.getId());
    assertNotNull(c2);
    assertEquals("435df2f061add3589cb326cc64be9b9c3897ceca", c2.getId());
  }

  @Test
  public void testGetAncestor()
  {
    LogCommandRequest request = new LogCommandRequest();

    request.setBranch("test-branch");
    request.setAncestorChangeset("master");

    ChangesetPagingResult result = createCommand().getChangesets(request);

    assertNotNull(result);
    assertEquals(1, result.getTotal());
    assertEquals(1, result.getChangesets().size());

    Changeset c = result.getChangesets().get(0);

    assertNotNull(c);
    assertEquals("3f76a12f08a6ba0dc988c68b7f0b2cd190efc3c4", c.getId());
  }

  @Test
  public void shouldFindDefaultBranchFromHEAD() throws Exception {
    setRepositoryHeadReference("ref: refs/heads/test-branch");

    ChangesetPagingResult changesets = createCommand().getChangesets(new LogCommandRequest());

    assertEquals("test-branch", changesets.getBranchName());
  }

  @Test
  public void shouldFindMasterBranchWhenHEADisNoRef() throws Exception {
    setRepositoryHeadReference("592d797cd36432e591416e8b2b98154f4f163411");

    ChangesetPagingResult changesets = createCommand().getChangesets(new LogCommandRequest());

    assertEquals("master", changesets.getBranchName());
  }

  private void setRepositoryHeadReference(String s) throws IOException {
    Files.write(s, repositoryHeadReferenceFile(), defaultCharset());
  }

  private File repositoryHeadReferenceFile() {
    return new File(repositoryDirectory, "HEAD");
  }

  private GitLogCommand createCommand()
  {
    return new GitLogCommand(createContext(), repository);
  }
}
