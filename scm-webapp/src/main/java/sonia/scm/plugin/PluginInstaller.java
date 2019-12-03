package sonia.scm.plugin;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import sonia.scm.SCMContextProvider;
import sonia.scm.net.ahc.AdvancedHttpClient;

import javax.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

@SuppressWarnings("UnstableApiUsage") // guava hash is marked as unstable
class PluginInstaller {

  private final SCMContextProvider context;
  private final AdvancedHttpClient client;

  @Inject
  public PluginInstaller(SCMContextProvider context, AdvancedHttpClient client) {
    this.context = context;
    this.client = client;
  }

  @SuppressWarnings("squid:S4790") // hashing should be safe
  public PendingPluginInstallation install(AvailablePlugin plugin) {
    Path file = null;
    try (HashingInputStream input = new HashingInputStream(Hashing.sha256(), download(plugin))) {
      file = createFile(plugin);
      Files.copy(input, file);

      verifyChecksum(plugin, input.hash(), file);
      return new PendingPluginInstallation(plugin.install(), file);
    } catch (IOException ex) {
      cleanup(file);
      throw new PluginDownloadException(plugin.getDescriptor().getInformation(), ex);
    }
  }

  private void cleanup(Path file) {
    try {
      if (file != null) {
        Files.deleteIfExists(file);
      }
    } catch (IOException e) {
      throw new PluginCleanupException(e);
    }
  }

  private void verifyChecksum(AvailablePlugin plugin, HashCode hash, Path file) {
    Optional<String> checksum = plugin.getDescriptor().getChecksum();
    if (checksum.isPresent()) {
      String calculatedChecksum = hash.toString();
      if (!checksum.get().equalsIgnoreCase(calculatedChecksum)) {
        cleanup(file);
        throw new PluginChecksumMismatchException(plugin.getDescriptor().getInformation(), calculatedChecksum, checksum.get());
      }
    }
  }

  private InputStream download(AvailablePlugin plugin) throws IOException {
    return client.get(plugin.getDescriptor().getUrl()).request().contentAsStream();
  }

  private Path createFile(AvailablePlugin plugin) throws IOException {
    Path directory = context.resolve(Paths.get("plugins"));
    Files.createDirectories(directory);
    return directory.resolve(plugin.getDescriptor().getInformation().getName() + ".smp");
  }
}
