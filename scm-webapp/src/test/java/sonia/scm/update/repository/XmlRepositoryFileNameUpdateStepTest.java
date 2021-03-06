package sonia.scm.update.repository;

import com.google.common.io.Resources;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junitpioneer.jupiter.TempDirectory;
import sonia.scm.SCMContextProvider;
import sonia.scm.repository.xml.PathBasedRepositoryLocationResolver;
import sonia.scm.repository.xml.XmlRepositoryDAO;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(TempDirectory.class)
class XmlRepositoryFileNameUpdateStepTest {

  SCMContextProvider contextProvider = mock(SCMContextProvider.class);
  XmlRepositoryDAO repositoryDAO = mock(XmlRepositoryDAO.class);

  @BeforeEach
  void mockScmHome(@TempDirectory.TempDir Path tempDir) {
    when(contextProvider.getBaseDirectory()).thenReturn(tempDir.toFile());
  }

  @Test
  void shouldCopyRepositoriesFileToRepositoryPathsFile(@TempDirectory.TempDir Path tempDir) throws IOException {
    XmlRepositoryFileNameUpdateStep updateStep = new XmlRepositoryFileNameUpdateStep(contextProvider, repositoryDAO);
    URL url = Resources.getResource("sonia/scm/update/repository/formerV2RepositoryFile.xml");
    Path configDir = tempDir.resolve("config");
    Files.createDirectories(configDir);
    Files.copy(url.openStream(), configDir.resolve("repositories.xml"));

    updateStep.doUpdate();

    assertThat(configDir.resolve(PathBasedRepositoryLocationResolver.STORE_NAME + ".xml")).exists();
    assertThat(configDir.resolve("repositories.xml")).doesNotExist();
    verify(repositoryDAO).refresh();
  }
}
