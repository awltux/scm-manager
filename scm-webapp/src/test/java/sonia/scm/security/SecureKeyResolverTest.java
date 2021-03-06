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



package sonia.scm.security;

//~--- non-JDK imports --------------------------------------------------------

import io.jsonwebtoken.Jwts;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import sonia.scm.store.ConfigurationEntryStore;
import sonia.scm.store.ConfigurationEntryStoreFactory;

import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 *
 * @author Sebastian Sdorra
 */
@RunWith(MockitoJUnitRunner.class)
public class SecureKeyResolverTest
{

  /**
   * Method description
   *
   */
  @Test
  public void testGetSecureKey()
  {
    SecureKey key = resolver.getSecureKey("test");

    assertNotNull(key);
    when(store.get("test")).thenReturn(key);

    SecureKey sameKey = resolver.getSecureKey("test");

    assertSame(key, sameKey);
  }

  /**
   * Method description
   *
   */
  @Test
  public void testResolveSigningKeyBytes()
  {
    SecureKey key = resolver.getSecureKey("test");

    when(store.get("test")).thenReturn(key);

    byte[] bytes = resolver.resolveSigningKeyBytes(null,
                     Jwts.claims().setSubject("test"));

    assertArrayEquals(key.getBytes(), bytes);
  }

  /**
   * Method description
   *
   */
  @Test
  public void testResolveSigningKeyBytesWithoutKey()
  {
    byte[] bytes = resolver.resolveSigningKeyBytes(null, Jwts.claims().setSubject("test"));
    assertThat(bytes[0]).isEqualTo((byte) 42);
  }

  /**
   * Method description
   *
   */
  @Test(expected = IllegalArgumentException.class)
  public void testResolveSigningKeyBytesWithoutSubject()
  {
    resolver.resolveSigningKeyBytes(null, Jwts.claims());
  }

  //~--- set methods ----------------------------------------------------------

  /**
   * Method description
   *
   */
  @Before
  public void setUp()
  {
    ConfigurationEntryStoreFactory factory = mock(ConfigurationEntryStoreFactory.class);

    when(factory.withType(any())).thenCallRealMethod();
    when(factory.<SecureKey>getStore(argThat(storeParameters -> {
      assertThat(storeParameters.getName()).isEqualTo(SecureKeyResolver.STORE_NAME);
      assertThat(storeParameters.getType()).isEqualTo(SecureKey.class);
      return true;
    }))).thenReturn(store);
    Random random = mock(Random.class);
    doAnswer(invocation -> ((byte[]) invocation.getArguments()[0])[0] = 42).when(random).nextBytes(any());
    resolver = new SecureKeyResolver(factory, random);
  }

  //~--- fields ---------------------------------------------------------------

  /** Field description */
  private SecureKeyResolver resolver;

  /** Field description */
  @Mock
  private ConfigurationEntryStore<SecureKey> store;
}
