package sonia.scm.update.repository;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static java.util.Arrays.asList;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "repository-migration")
class RepositoryMigrationPlan {

  private List<RepositoryMigrationEntry> entries;

  RepositoryMigrationPlan() {
    this(new RepositoryMigrationEntry[0]);
  }

  RepositoryMigrationPlan(RepositoryMigrationEntry... entries) {
    this.entries = new ArrayList<>(asList(entries));
  }

  Optional<RepositoryMigrationEntry> get(String repositoryId) {
    return entries.stream()
      .filter(repositoryEntry -> repositoryId.equals(repositoryEntry.repositoryId))
      .findFirst();
  }

  public Collection<RepositoryMigrationEntry> getEntries() {
    return Collections.unmodifiableList(entries);
  }

  public void set(String repositoryId, String protocol, String originalName, MigrationStrategy strategy, String newNamespace, String newName) {
    Optional<RepositoryMigrationEntry> entry = get(repositoryId);
    if (entry.isPresent()) {
      entry.get().setStrategy(strategy);
      entry.get().setNewNamespace(newNamespace);
      entry.get().setNewName(newName);
    } else {
      entries.add(new RepositoryMigrationEntry(repositoryId, protocol, originalName, strategy, newNamespace, newName));
    }
  }

  @XmlRootElement(name = "entries")
  @XmlAccessorType(XmlAccessType.FIELD)
  static class RepositoryMigrationEntry {

    private String repositoryId;
    private String protocol;
    private String originalName;
    private MigrationStrategy dataMigrationStrategy;
    private String newNamespace;
    private String newName;

    RepositoryMigrationEntry() {
    }

    RepositoryMigrationEntry(String repositoryId, String protocol, String originalName, MigrationStrategy dataMigrationStrategy, String newNamespace, String newName) {
      this.repositoryId = repositoryId;
      this.protocol = protocol;
      this.originalName = originalName;
      this.dataMigrationStrategy = dataMigrationStrategy;
      this.newNamespace = newNamespace;
      this.newName = newName;
    }

    public String getRepositoryId() {
      return repositoryId;
    }

    public String getProtocol() {
      return protocol;
    }

    public String getOriginalName() {
      return originalName;
    }

    public MigrationStrategy getDataMigrationStrategy() {
      return dataMigrationStrategy;
    }

    public String getNewNamespace() {
      return newNamespace;
    }

    public String getNewName() {
      return newName;
    }

    private void setStrategy(MigrationStrategy strategy) {
      this.dataMigrationStrategy = strategy;
    }

    private void setNewNamespace(String newNamespace) {
      this.newNamespace = newNamespace;
    }

    private void setNewName(String newName) {
      this.newName = newName;
    }
  }
}
