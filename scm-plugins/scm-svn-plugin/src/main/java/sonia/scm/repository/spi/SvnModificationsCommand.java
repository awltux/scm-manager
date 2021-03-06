package sonia.scm.repository.spi;

import lombok.extern.slf4j.Slf4j;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNLogEntry;
import org.tmatesoft.svn.core.io.SVNRepository;
import org.tmatesoft.svn.core.wc.SVNClientManager;
import org.tmatesoft.svn.core.wc.admin.SVNLookClient;
import sonia.scm.repository.InternalRepositoryException;
import sonia.scm.repository.Modifications;
import sonia.scm.repository.Repository;
import sonia.scm.repository.SvnUtil;
import sonia.scm.util.Util;

import java.util.Collection;

@Slf4j
public class SvnModificationsCommand extends AbstractSvnCommand implements ModificationsCommand {

  SvnModificationsCommand(SvnContext context, Repository repository) {
    super(context, repository);
  }

  @Override
  public Modifications getModifications(String revisionOrTransactionId) {
    Modifications modifications;
    try {
      if (SvnUtil.isTransactionEntryId(revisionOrTransactionId)) {
        modifications = getModificationsFromTransaction(SvnUtil.getTransactionId(revisionOrTransactionId));
      } else {
        modifications = getModificationFromRevision(revisionOrTransactionId);
      }
      return modifications;
    } catch (SVNException ex) {
      throw new InternalRepositoryException(
        repository,
        "failed to get svn modifications for " + revisionOrTransactionId,
        ex
      );
    }
  }

  @SuppressWarnings("unchecked")
  private Modifications getModificationFromRevision(String revision) throws SVNException {
    log.debug("get svn modifications from revision: {}", revision);
    long revisionNumber = SvnUtil.getRevisionNumber(revision, repository);
    SVNRepository repo = open();
    Collection<SVNLogEntry> entries = repo.log(null, null, revisionNumber,
      revisionNumber, true, true);
    if (Util.isNotEmpty(entries)) {
      return SvnUtil.createModifications(entries.iterator().next(), revision);
    }
    return null;
  }

  private Modifications getModificationsFromTransaction(String transaction) throws SVNException {
    log.debug("get svn modifications from transaction: {}", transaction);
    final Modifications modifications = new Modifications();
    SVNLookClient client = SVNClientManager.newInstance().getLookClient();
    client.doGetChanged(context.getDirectory(), transaction,
      e -> SvnUtil.appendModification(modifications, e.getType(), e.getPath()), true);

    return modifications;
  }

  @Override
  public Modifications getModifications(ModificationsCommandRequest request) {
    return getModifications(request.getRevision());
  }

}
