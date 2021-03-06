package sonia.scm.repository.util;


import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import sonia.scm.repository.Repository;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SimpleWorkdirFactoryTest {

  private static final Repository REPOSITORY = new Repository("1", "git", "space", "X");

  private final Closeable parent = mock(Closeable.class);
  private final Closeable clone = mock(Closeable.class);

  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();
  private SimpleWorkdirFactory<Closeable, Closeable, Context> simpleWorkdirFactory;

  private String initialBranchForLastCloneCall;

  @Before
  public void initFactory() throws IOException {
    WorkdirProvider workdirProvider = new WorkdirProvider(temporaryFolder.newFolder());
    simpleWorkdirFactory = new SimpleWorkdirFactory<Closeable, Closeable, Context>(workdirProvider) {
      @Override
      protected Repository getScmRepository(Context context) {
        return REPOSITORY;
      }

      @Override
      protected void closeRepository(Closeable repository) throws IOException {
        repository.close();
      }

      @Override
      protected void closeWorkdirInternal(Closeable workdir) throws Exception {
        workdir.close();
      }

      @Override
      protected ParentAndClone<Closeable, Closeable> cloneRepository(Context context, File target, String initialBranch) {
        initialBranchForLastCloneCall = initialBranch;
        return new ParentAndClone<>(parent, clone);
      }
    };
  }

  @Test
  public void shouldCreateParentAndClone() {
    Context context = new Context();
    try (WorkingCopy<Closeable, Closeable> workingCopy = simpleWorkdirFactory.createWorkingCopy(context, null)) {
      assertThat(workingCopy.getCentralRepository()).isSameAs(parent);
      assertThat(workingCopy.getWorkingRepository()).isSameAs(clone);
    }
  }

  @Test
  public void shouldCloseParent() throws IOException {
    Context context = new Context();
    try (WorkingCopy<Closeable, Closeable> workingCopy = simpleWorkdirFactory.createWorkingCopy(context, null)) {}

    verify(parent).close();
  }

  @Test
  public void shouldCloseClone() throws IOException {
    Context context = new Context();
    try (WorkingCopy<Closeable, Closeable> workingCopy = simpleWorkdirFactory.createWorkingCopy(context, null)) {}

    verify(clone).close();
  }

  @Test
  public void shouldPropagateInitialBranch() {
    Context context = new Context();
    try (WorkingCopy<Closeable, Closeable> workingCopy = simpleWorkdirFactory.createWorkingCopy(context, "some")) {
      assertThat(initialBranchForLastCloneCall).isEqualTo("some");
    }
  }

  private static class Context {}
}
