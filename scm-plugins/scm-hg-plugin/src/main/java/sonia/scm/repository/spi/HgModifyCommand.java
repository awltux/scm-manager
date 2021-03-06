package sonia.scm.repository.spi;

import com.aragost.javahg.Changeset;
import com.aragost.javahg.Repository;
import com.aragost.javahg.commands.CommitCommand;
import com.aragost.javahg.commands.ExecutionException;
import com.aragost.javahg.commands.PullCommand;
import com.aragost.javahg.commands.RemoveCommand;
import com.aragost.javahg.commands.StatusCommand;
import sonia.scm.NoChangesMadeException;
import sonia.scm.repository.InternalRepositoryException;
import sonia.scm.repository.util.WorkingCopy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class HgModifyCommand implements ModifyCommand {

  private HgCommandContext context;
  private final HgWorkdirFactory workdirFactory;

  public HgModifyCommand(HgCommandContext context, HgWorkdirFactory workdirFactory) {
    this.context = context;
    this.workdirFactory = workdirFactory;
  }

  @Override
  public String execute(ModifyCommandRequest request) {

    try (WorkingCopy<com.aragost.javahg.Repository, com.aragost.javahg.Repository> workingCopy = workdirFactory.createWorkingCopy(context, request.getBranch())) {
      Repository workingRepository = workingCopy.getWorkingRepository();
      request.getRequests().forEach(
        partialRequest -> {
          try {
            partialRequest.execute(new ModifyWorkerHelper() {

              @Override
              public void addFileToScm(String name, Path file) {
                try {
                  addFileToHg(file.toFile());
                } catch (ExecutionException e) {
                  throwInternalRepositoryException("could not add new file to index", e);
                }
              }

              @Override
              public void doScmDelete(String toBeDeleted) {
                RemoveCommand.on(workingRepository).execute(toBeDeleted);
              }

              @Override
              public sonia.scm.repository.Repository getRepository() {
                return context.getScmRepository();
              }

              @Override
              public String getBranch() {
                return request.getBranch();
              }

              public File getWorkDir() {
                return workingRepository.getDirectory();
              }

              private void addFileToHg(File file) {
                workingRepository.workingCopy().add(file.getAbsolutePath());
              }
            });
          } catch (IOException e) {
            throwInternalRepositoryException("could not execute command on repository", e);
          }
        }
      );
      if (StatusCommand.on(workingRepository).lines().isEmpty()) {
        throw new NoChangesMadeException(context.getScmRepository());
      }
      CommitCommand.on(workingRepository).user(String.format("%s <%s>", request.getAuthor().getName(), request.getAuthor().getMail())).message(request.getCommitMessage()).execute();
      List<Changeset> execute = pullModifyChangesToCentralRepository(request, workingCopy);
      return execute.get(0).getNode();
    } catch (ExecutionException e) {
      throwInternalRepositoryException("could not execute command on repository", e);
      return null;
    }
  }

  private List<Changeset> pullModifyChangesToCentralRepository(ModifyCommandRequest request, WorkingCopy<com.aragost.javahg.Repository, com.aragost.javahg.Repository> workingCopy) {
    try {
      com.aragost.javahg.commands.PullCommand pullCommand = PullCommand.on(workingCopy.getCentralRepository());
      workdirFactory.configure(pullCommand);
      return pullCommand.execute(workingCopy.getDirectory().getAbsolutePath());
    } catch (Exception e) {
      throw new IntegrateChangesFromWorkdirException(context.getScmRepository(),
        String.format("Could not pull modify changes from working copy to central repository for branch %s", request.getBranch()),
        e);
    }
  }

  private String throwInternalRepositoryException(String message, Exception e) {
    throw new InternalRepositoryException(context.getScmRepository(), message, e);
  }
}
