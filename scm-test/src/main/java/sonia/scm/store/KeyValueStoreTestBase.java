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


package sonia.scm.store;

//~--- non-JDK imports --------------------------------------------------------

import org.junit.Before;
import org.junit.Test;

import sonia.scm.AbstractTestBase;
import sonia.scm.repository.Repository;
import sonia.scm.repository.RepositoryTestData;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

//~--- JDK imports ------------------------------------------------------------

import java.util.Map;

/**
 *
 * @author Sebastian Sdorra
 */
public abstract class KeyValueStoreTestBase extends AbstractTestBase
{

  protected Repository repository = RepositoryTestData.createHeartOfGold();
  protected DataStore<StoreObject> store;
  protected DataStore<StoreObject> repoStore;
  protected String repoStoreName = "testRepoStore";
  protected String storeName = "testStore";

  /**
   * Method description
   *
   *
   * @return
   */
  protected abstract <STORE_OBJECT> DataStore<STORE_OBJECT> getDataStore(Class<STORE_OBJECT> type , Repository repository);
  protected abstract <STORE_OBJECT> DataStore<STORE_OBJECT> getDataStore(Class<STORE_OBJECT> type );


  //~--- methods --------------------------------------------------------------

  /**
   * Method description
   *
   */
  @Before
  public void before()
  {
    store = getDataStore(StoreObject.class);
    repoStore = getDataStore(StoreObject.class, repository);
    store.clear();
    repoStore.clear();
  }

  /**
   * Method description
   *
   */
  @Test
  public void testClear()
  {
    testPutWithId();

    store.clear();
    assertNull(store.get("1"));
    assertNull(store.get("2"));

    assertTrue(store.getAll().isEmpty());
  }

  /**
   * Method description
   *
   */
  @Test
  public void testGet()
  {
    StoreObject other = store.get("1");

    assertNull(other);

    StoreObject obj = new StoreObject("test-1");

    store.put("1", obj);
    other = store.get("1");
    assertNotNull(other);
    assertEquals(obj, other);
  }

  /**
   * Method description
   *
   */
  @Test
  public void testGetAll()
  {
    StoreObject obj1 = new StoreObject("test-1");

    store.put("1", obj1);

    StoreObject obj2 = new StoreObject("test-2");

    store.put("2", obj2);

    Map<String, StoreObject> map = store.getAll();

    assertNotNull(map);

    assertFalse(map.isEmpty());
    assertEquals(2, map.size());

    assertEquals(obj1, map.get("1"));
    assertEquals(obj2, map.get("2"));

    assertNull(map.get("3"));
  }

  /**
   * Method description
   *
   */
  @Test
  public void testGetAllFromEmpty()
  {
    Map<String, StoreObject> map = store.getAll();

    assertNotNull(map);
    assertTrue(map.isEmpty());
  }

  /**
   * Method description
   *
   */
  @Test
  public void testGetFromEmpty()
  {
    StoreObject obj = store.get("test");

    assertNull(obj);
  }

  /**
   * Method description
   *
   */
  @Test
  public void testPutWithId()
  {
    StoreObject obj1 = new StoreObject("test-1");

    store.put("1", obj1);

    StoreObject obj2 = new StoreObject("test-2");

    store.put("2", obj2);

    assertEquals(obj1, store.get("1"));
    assertEquals(obj2, store.get("2"));
  }

  /**
   * Method description
   *
   */
  @Test
  public void testPutWithoutId()
  {
    StoreObject obj = new StoreObject("test-1");
    String id = store.put(obj);

    assertNotNull(id);

    assertEquals(obj, store.get(id));
  }

  /**
   * Method description
   *
   */
  @Test
  public void testRemove()
  {
    testPutWithId();

    store.remove("1");
    assertNull(store.get("1"));
    assertNotNull(store.get("2"));
    store.remove("2");
    assertNull(store.get("2"));
  }


}
