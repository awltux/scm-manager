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

/**
 * The ConfigurationStoreFactory can be used to create new or get existing {@link ConfigurationStore} objects.
 * <br>
 * <b>Note:</b> the default implementation uses the same location as the {@link ConfigurationEntryStoreFactory}, so be
 * sure that the store names are unique for all {@link ConfigurationEntryStore}s and {@link ConfigurationStore}s.
 * <br>
 * You can either create a global {@link ConfigurationStore} or a {@link ConfigurationStore} for a specific repository.
 * To create a global {@link ConfigurationStore} call:
 * <code><pre>
 *     configurationStoreFactory
 *       .withType(PersistedType.class)
 *       .withName("name")
 *       .build();
 * </pre></code>
 * To create a {@link ConfigurationStore} for a specific repository call:
 * <code><pre>
 *     configurationStoreFactory
 *       .withType(PersistedType.class)
 *       .withName("name")
 *       .forRepository(repository)
 *       .build();
 * </pre></code>
 *
 * @author Sebastian Sdorra
 * 
 * @apiviz.landmark
 * @apiviz.uses sonia.scm.store.ConfigurationStore
 */
public interface ConfigurationStoreFactory {

  /**
   * Creates a new or gets an existing {@link ConfigurationStore}. Instead of calling this method you should use the
   * floating API from {@link #withType(Class)}.
   *
   * @param storeParameters The parameters for the {@link ConfigurationStore}.
   * @return A new or an existing {@link ConfigurationStore} for the given parameters.
   */
  <T> ConfigurationStore<T> getStore(final TypedStoreParameters<T> storeParameters);

  /**
   * Use this to create a new or get an existing {@link ConfigurationStore} with a floating API.
   * @param type The type for the {@link ConfigurationStore}.
   * @return Floating API to set the name and either specify a repository or directly build a global
   * {@link ConfigurationStore}.
   */
  default <T> TypedFloatingStoreParameters<T, ConfigurationStore<T>>.Builder withType(Class<T> type) {
    return new TypedFloatingStoreParameters<T, ConfigurationStore<T>>(this::getStore).new Builder(type);
  }
}
