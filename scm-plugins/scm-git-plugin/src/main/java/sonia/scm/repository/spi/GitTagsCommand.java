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

import com.google.common.base.Function;
import com.google.common.collect.Lists;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.Ref;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.repository.GitUtil;
import sonia.scm.repository.InternalRepositoryException;
import sonia.scm.repository.Repository;
import sonia.scm.repository.Tag;

import java.io.IOException;
import java.util.List;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 */
public class GitTagsCommand extends AbstractGitCommand implements TagsCommand
{

  /**
   * Constructs ...
   *
   *
   * @param context
   * @param repository
   */
  public GitTagsCommand(GitContext context, Repository repository)
  {
    super(context, repository);
  }

  //~--- get methods ----------------------------------------------------------

  @Override
  public List<Tag> getTags() throws IOException
  {
    List<Tag> tags = null;

    RevWalk revWalk = null;

    try
    {
      final Git git = new Git(open());

      revWalk = new RevWalk(git.getRepository());

      List<Ref> tagList = git.tagList().call();

      tags = Lists.transform(tagList,
        new TransformFuntion(git.getRepository(), revWalk));
    }
    catch (GitAPIException ex)
    {
      throw new InternalRepositoryException(repository, "could not read tags from repository", ex);
    }
    finally
    {
      GitUtil.release(revWalk);
    }

    return tags;
  }

  //~--- inner classes --------------------------------------------------------

  /**
   * Class description
   *
   *
   * @version        Enter version here..., 12/07/06
   * @author         Enter your name here...
   */
  private static class TransformFuntion implements Function<Ref, Tag>
  {

    /**
     * the logger for TransformFuntion
     */
    private static final Logger logger =
      LoggerFactory.getLogger(TransformFuntion.class);

    //~--- constructors -------------------------------------------------------

    /**
     * Constructs ...
     *
     *
     * @param repository
     * @param revWalk
     */
    public TransformFuntion(org.eclipse.jgit.lib.Repository repository,
      RevWalk revWalk)
    {
      this.repository = repository;
      this.revWalk = revWalk;
    }

    //~--- methods ------------------------------------------------------------

    /**
     * Method description
     *
     *
     * @param ref
     *
     * @return
     */
    @Override
    public Tag apply(Ref ref)
    {
      Tag tag = null;

      try
      {
        RevCommit commit = GitUtil.getCommit(repository, revWalk, ref);

        if (commit != null)
        {
          String name = GitUtil.getTagName(ref);

          tag = new Tag(name, commit.getId().name());
        }

      }
      catch (IOException ex)
      {
        logger.error("could not get commit for tag", ex);
      }

      return tag;
    }

    //~--- fields -------------------------------------------------------------

    /** Field description */
    private org.eclipse.jgit.lib.Repository repository;

    /** Field description */
    private RevWalk revWalk;
  }
}
