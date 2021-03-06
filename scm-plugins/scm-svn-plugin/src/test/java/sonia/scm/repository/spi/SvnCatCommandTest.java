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

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import sonia.scm.NotFoundException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;

//~--- JDK imports ------------------------------------------------------------

public class SvnCatCommandTest extends AbstractSvnCommandTestBase {

  @Rule
  public final ExpectedException expectedException = ExpectedException.none();

  @Test
  public void testCat() {
    CatCommandRequest request = new CatCommandRequest();

    request.setPath("a.txt");
    request.setRevision("1");
    assertEquals("a", execute(request));
  }

  @Test
  public void testSimpleCat() {
    CatCommandRequest request = new CatCommandRequest();

    request.setPath("c/d.txt");
    assertEquals("d", execute(request));
  }

  @Test
  public void testUnknownFile() {
    CatCommandRequest request = new CatCommandRequest();

    request.setPath("unknown");
    request.setRevision("1");

    expectedException.expect(new BaseMatcher<Object>() {
      @Override
      public void describeTo(Description description) {
        description.appendText("expected NotFoundException for path");
      }

      @Override
      public boolean matches(Object item) {
        return "Path".equals(((NotFoundException)item).getContext().get(0).getType());
      }
    });

    execute(request);
  }

  @Test
  public void testUnknownRevision() {
    CatCommandRequest request = new CatCommandRequest();

    request.setPath("a.txt");
    request.setRevision("42");

    expectedException.expect(new BaseMatcher<Object>() {
      @Override
      public void describeTo(Description description) {
        description.appendText("expected NotFoundException for revision");
      }

      @Override
      public boolean matches(Object item) {
        return "Revision".equals(((NotFoundException)item).getContext().get(0).getType());
      }
    });

    execute(request);
  }

  @Test
  public void testSimpleStream() throws IOException {
    CatCommandRequest request = new CatCommandRequest();
    request.setPath("a.txt");
    request.setRevision("1");

    InputStream catResultStream = new SvnCatCommand(createContext(), repository).getCatResultStream(request);

    assertEquals('a', catResultStream.read());
    assertEquals('\n', catResultStream.read());
    assertEquals(-1, catResultStream.read());

    catResultStream.close();
  }

  private String execute(CatCommandRequest request) {
    String content = null;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    try
    {
      new SvnCatCommand(createContext(), repository).getCatResult(request,
                        baos);
    }
    finally
    {
      content = baos.toString().trim();
    }

    return content;
  }
}
