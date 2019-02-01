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



package sonia.scm.repository;

import com.github.sdorra.ssp.PermissionObject;
import com.github.sdorra.ssp.StaticPermissions;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import sonia.scm.BasicPropertiesAware;
import sonia.scm.ModelObject;
import sonia.scm.util.Util;
import sonia.scm.util.ValidationUtil;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Source code repository.
 *
 * @author Sebastian Sdorra
 */
@StaticPermissions(
  value = "repository",
  permissions = {"read", "modify", "delete", "healthCheck", "pull", "push", "permissionRead", "permissionWrite"}
)
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "repositories")
public class Repository extends BasicPropertiesAware implements ModelObject, PermissionObject{

  private static final long serialVersionUID = 3486560714961909711L;

  private String contact;
  private Long creationDate;
  private String description;
  @XmlElement(name = "healthCheckFailure")
  @XmlElementWrapper(name = "healthCheckFailures")
  private List<HealthCheckFailure> healthCheckFailures;
  private String id;
  private Long lastModified;
  private String namespace;
  private String name;
  @XmlElement(name = "permission")
  private final Set<RepositoryPermission> permissions = new HashSet<>();
  @XmlElement(name = "public")
  private boolean publicReadable = false;
  private boolean archived = false;
  private String type;


  /**
   * Constructs a new {@link Repository}.
   * This constructor is used by JAXB.
   */
  public Repository() {
  }

  /**
   * Constructs a new {@link Repository}.
   *
   * @param id   id of the {@link Repository}
   * @param type type of the {@link Repository}
   * @param name name of the {@link Repository}
   */
  public Repository(String id, String type, String namespace, String name) {
    this.id = id;
    this.type = type;
    this.namespace = namespace;
    this.name = name;
  }

  /**
   * Constructs a new {@link Repository}.
   *
   * @param id          id of the {@link Repository}
   * @param type        type of the {@link Repository}
   * @param name        name of the {@link Repository}
   * @param namespace   namespace of the {@link Repository}
   * @param contact     email address of a person who is responsible for
   *                    this repository.
   * @param description a short description of the repository
   * @param permissions permissions for specific users and groups.
   */
  public Repository(String id, String type, String namespace, String name, String contact,
                    String description, RepositoryPermission... permissions) {
    this.id = id;
    this.type = type;
    this.namespace = namespace;
    this.name = name;
    this.contact = contact;
    this.description = description;

    if (Util.isNotEmpty(permissions)) {
      this.permissions.addAll(Arrays.asList(permissions));
    }
  }

  /**
   * Returns a contact email address of a person who is responsible for
   * the {@link Repository}.
   *
   * @return contact email address
   */
  public String getContact() {
    return contact;
  }

  /**
   * Returns a timestamp of the creation date of the {@link Repository}.
   *
   * @return a timestamp of the creation date of the {@link Repository}
   */
  public Long getCreationDate() {
    return creationDate;
  }

  /**
   * Returns a short description of the {@link Repository}.
   *
   * @return short description
   */
  public String getDescription() {
    return description;
  }

  /**
   * Returns a {@link List} of {@link HealthCheckFailure}s. The {@link List}
   * is empty if the repository is healthy.
   *
   * @return {@link List} of {@link HealthCheckFailure}s
   * @since 1.36
   */
  @SuppressWarnings("unchecked")
  public List<HealthCheckFailure> getHealthCheckFailures() {
    if (healthCheckFailures == null) {
      healthCheckFailures = Collections.EMPTY_LIST;
    }

    return healthCheckFailures;
  }

  @Override
  public String getId() {
    return id;
  }

  @Override
  public Long getLastModified() {
    return lastModified;
  }


  public String getName() {
    return name;
  }

  public String getNamespace() { return namespace; }

  @XmlTransient
  public NamespaceAndName getNamespaceAndName() {
    return new NamespaceAndName(getNamespace(), getName());
  }

  public Collection<RepositoryPermission> getPermissions() {
    return Collections.unmodifiableCollection(permissions);
  }

  /**
   * Returns the type (hg, git, svn ...) of the {@link Repository}.
   *
   * @return type of the repository
   */
  @Override
  public String getType() {
    return type;
  }

  /**
   * Returns true if the repository is archived.
   *
   * @return true if the repository is archived
   * @since 1.14
   */
  public boolean isArchived() {
    return archived;
  }

  /**
   * Returns {@code true} if the repository is healthy.
   *
   * @return {@code true} if the repository is healthy
   * @since 1.36
   */
  public boolean isHealthy() {
    return Util.isEmpty(healthCheckFailures);
  }

  /**
   * Returns true if the {@link Repository} is public readable.
   *
   * @return true if the {@link Repository} is public readable
   */
  public boolean isPublicReadable() {
    return publicReadable;
  }

  /**
   * Returns true if the {@link Repository} is valid.
   * <ul>
   * <li>The name is not empty and contains only A-z, 0-9, _, -, /</li>
   * <li>The type is not empty</li>
   * <li>The contact is empty or contains a valid email address</li>
   * </ul>
   *
   * @return true if the {@link Repository} is valid
   */
  @Override
  public boolean isValid() {
    return ValidationUtil.isRepositoryNameValid(name) && Util.isNotEmpty(type)
      && ((Util.isEmpty(contact))
      || ValidationUtil.isMailAddressValid(contact));
  }

  /**
   * Archive or un archive this repository.
   *
   * @param archived true to enable archive
   * @since 1.14
   */
  public void setArchived(boolean archived) {
    this.archived = archived;
  }

  public void setContact(String contact) {
    this.contact = contact;
  }

  public void setCreationDate(Long creationDate) {
    this.creationDate = creationDate;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public void setId(String id) {
    this.id = id;
  }

  public void setLastModified(Long lastModified) {
    this.lastModified = lastModified;
  }

  public void setNamespace(String namespace) { this.namespace = namespace; }

  public void setName(String name) {
    this.name = name;
  }

  public void setPermissions(Collection<RepositoryPermission> permissions) {
    this.permissions.clear();
    this.permissions.addAll(permissions);
  }

  public void addPermission(RepositoryPermission newPermission) {
    this.permissions.add(newPermission);
  }

  public void removePermission(RepositoryPermission permission) {
    this.permissions.remove(permission);
  }

  public void setPublicReadable(boolean publicReadable) {
    this.publicReadable = publicReadable;
  }

  public void setType(String type) {
    this.type = type;
  }

  public void setHealthCheckFailures(List<HealthCheckFailure> healthCheckFailures) {
    this.healthCheckFailures = healthCheckFailures;
  }

  @Override
  public Repository clone() {
    Repository repository = null;

    try {
      repository = (Repository) super.clone();
    } catch (CloneNotSupportedException ex) {
      throw new RuntimeException(ex);
    }

    return repository;
  }

  /**
   * Copies all properties of the {@link Repository} to the given one.
   *
   * @param repository the target {@link Repository}
   */
  public void copyProperties(Repository repository) {
    repository.setNamespace(namespace);
    repository.setName(name);
    repository.setContact(contact);
    repository.setCreationDate(creationDate);
    repository.setLastModified(lastModified);
    repository.setDescription(description);
    repository.setPermissions(permissions);
    repository.setPublicReadable(publicReadable);
    repository.setArchived(archived);

    // do not copy health check results
  }

  /**
   * Returns true if the {@link Repository} is the same as the obj argument.
   *
   * @param obj the reference object with which to compare
   * @return true if the {@link Repository} is the same as the obj argument
   */
  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }

    if (getClass() != obj.getClass()) {
      return false;
    }

    final Repository other = (Repository) obj;

    return Objects.equal(id, other.id)
      && Objects.equal(namespace, other.namespace)
      && Objects.equal(name, other.name)
      && Objects.equal(contact, other.contact)
      && Objects.equal(description, other.description)
      && Objects.equal(publicReadable, other.publicReadable)
      && Objects.equal(archived, other.archived)
      && Objects.equal(permissions, other.permissions)
      && Objects.equal(type, other.type)
      && Objects.equal(creationDate, other.creationDate)
      && Objects.equal(lastModified, other.lastModified)
      && Objects.equal(properties, other.properties)
      && Objects.equal(healthCheckFailures, other.healthCheckFailures);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id, namespace, name, contact, description, publicReadable,
      archived, permissions, type, creationDate, lastModified, properties,
      healthCheckFailures);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
      .add("id", id)
      .add("namespace", namespace)
      .add("name", name)
      .add("contact", contact)
      .add("description", description)
      .add("publicReadable", publicReadable)
      .add("archived", archived)
      .add("permissions", permissions)
      .add("type", type)
      .add("lastModified", lastModified)
      .add("creationDate", creationDate)
      .add("properties", properties)
      .add("healthCheckFailures", healthCheckFailures)
      .toString();
  }
}
