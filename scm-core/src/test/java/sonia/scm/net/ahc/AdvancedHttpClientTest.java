/**
 * Copyright (c) 2014, Sebastian Sdorra
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

package sonia.scm.net.ahc;

import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 *
 * @author Sebastian Sdorra
 */
@RunWith(MockitoJUnitRunner.class)
public class AdvancedHttpClientTest {

  @Mock(answer = Answers.CALLS_REAL_METHODS)
  private AdvancedHttpClient client;

  private static final String URL = "https://www.scm-manager.org";
  
  @Test
  public void testGet()
  {
    AdvancedHttpRequest request = client.get(URL);
    assertEquals(URL, request.getUrl());
    assertEquals(HttpMethod.GET, request.getMethod());
  }
  
  @Test
  public void testDelete()
  {
    AdvancedHttpRequestWithBody request = client.delete(URL);
    assertEquals(URL, request.getUrl());
    assertEquals(HttpMethod.DELETE, request.getMethod());
  }
  
  @Test
  public void testPut()
  {
    AdvancedHttpRequestWithBody request = client.put(URL);
    assertEquals(URL, request.getUrl());
    assertEquals(HttpMethod.PUT, request.getMethod());
  }
  
  @Test
  public void testPost()
  {
    AdvancedHttpRequestWithBody request = client.post(URL);
    assertEquals(URL, request.getUrl());
    assertEquals(HttpMethod.POST, request.getMethod());
  }
  
  @Test
  public void testOptions()
  {
    AdvancedHttpRequestWithBody request = client.options(URL);
    assertEquals(URL, request.getUrl());
    assertEquals(HttpMethod.OPTIONS, request.getMethod());
  }
  
  @Test
  public void testHead()
  {
    AdvancedHttpRequest request = client.head(URL);
    assertEquals(URL, request.getUrl());
    assertEquals(HttpMethod.HEAD, request.getMethod());
  }
  
  @Test
  public void testMethod()
  {
    AdvancedHttpRequestWithBody request = client.method("PROPFIND", URL);
    assertEquals(URL, request.getUrl());
    assertEquals("PROPFIND", request.getMethod());
  }
}
