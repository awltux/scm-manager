package sonia.scm.update.group;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junitpioneer.jupiter.TempDirectory;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.group.Group;
import sonia.scm.group.xml.XmlGroupDAO;
import sonia.scm.store.ConfigurationEntryStore;
import sonia.scm.store.InMemoryConfigurationEntryStoreFactory;
import sonia.scm.update.UpdateStepTestUtil;
import sonia.scm.update.V1Properties;
import sonia.scm.update.V1Property;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static sonia.scm.store.InMemoryConfigurationEntryStoreFactory.create;

@ExtendWith(MockitoExtension.class)
@ExtendWith(TempDirectory.class)
class XmlGroupV1UpdateStepTest {

  @Mock
  XmlGroupDAO groupDAO;

  @Captor
  ArgumentCaptor<Group> groupCaptor;

  InMemoryConfigurationEntryStoreFactory storeFactory = create();

  XmlGroupV1UpdateStep updateStep;

  private UpdateStepTestUtil testUtil;


  @BeforeEach
  void mockScmHome(@TempDirectory.TempDir Path tempDir) {
    testUtil = new UpdateStepTestUtil(tempDir);
    updateStep = new XmlGroupV1UpdateStep(testUtil.getContextProvider(), groupDAO, storeFactory);
  }

  @Nested
  class WithExistingDatabase {

    @BeforeEach
    void captureStoredRepositories() {
      doNothing().when(groupDAO).add(groupCaptor.capture());
    }

    @BeforeEach
    void createGroupV1XML() throws IOException {
      testUtil.copyConfigFile("sonia/scm/update/group/groups.xml");
    }

    @Test
    void shouldCreateNewGroupFromGroupsV1Xml() throws JAXBException {
      updateStep.doUpdate();
      verify(groupDAO, times(2)).add(any());
    }

    @Test
    void shouldMapAttributesFromGroupsV1Xml() throws JAXBException {
      updateStep.doUpdate();
      Optional<Group> group = groupCaptor.getAllValues().stream().filter(u -> u.getName().equals("normals")).findFirst();
      assertThat(group)
        .get()
        .hasFieldOrPropertyWithValue("name", "normals")
        .hasFieldOrPropertyWithValue("description", "Normal people")
        .hasFieldOrPropertyWithValue("type", "xml")
        .hasFieldOrPropertyWithValue("members", asList("trillian", "dent"))
        .hasFieldOrPropertyWithValue("lastModified", 1559550955883L)
        .hasFieldOrPropertyWithValue("creationDate", 1559548942457L);
    }

    @Test
    void shouldExtractProperties() throws JAXBException {
      updateStep.doUpdate();
      ConfigurationEntryStore<V1Properties> propertiesStore = storeFactory.get("group-properties-v1");
      V1Properties properties = propertiesStore.get("normals");
      assertThat(properties).isNotNull();
      assertThat(properties.get("mostly")).isEqualTo("humans");
    }
  }

  @Nested
  class WithExistingDatabaseWithEmptyList {

    @BeforeEach
    void createGroupV1XML() throws IOException {
      testUtil.copyConfigFile("sonia/scm/update/group/groups_empty_groups.xml", "groups.xml");
    }

    @Test
    void shouldCreateNewGroupFromGroupsV1Xml() throws JAXBException {
      updateStep.doUpdate();
      verify(groupDAO, times(0)).add(any());
    }
  }

  @Nested
  class WithExistingDatabaseWithoutList {

    @BeforeEach
    void createGroupV1XML() throws IOException {
      testUtil.copyConfigFile("sonia/scm/update/group/groups_no_groups.xml", "groups.xml");
    }

    @Test
    void shouldCreateNewGroupFromGroupsV1Xml() throws JAXBException {
      updateStep.doUpdate();
      verify(groupDAO, times(0)).add(any());
    }
  }

  @Test
  void shouldNotFailForMissingConfigDir() throws JAXBException {
    updateStep.doUpdate();
  }
}
