package dev.cyberstamp.sigmund.resolver.connector;

import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.transfer.ArtifactTransferException;

/**
 * A downloaded artifact did not pass Sigmund verification, or its signatures could not be fetched to verify it.
 * The artifact is not kept in the local repository.
 */
public class SigmundVerificationException extends ArtifactTransferException {

    /**
     * Creates the exception for an artifact the policy blocks.
     *
     * @param artifact the artifact that failed verification
     * @param repository the repository it was downloaded from
     * @param message the description of the verification result
     */
    public SigmundVerificationException(Artifact artifact, RemoteRepository repository, String message) {
        super(artifact, repository, message);
    }

    /**
     * Creates the exception for an artifact that could not be verified because of an underlying failure.
     *
     * @param artifact the artifact that could not be verified
     * @param repository the repository it was downloaded from
     * @param message what went wrong
     * @param cause the underlying failure, such as a signature transfer error
     */
    public SigmundVerificationException(
            Artifact artifact, RemoteRepository repository, String message, Throwable cause) {
        super(artifact, repository, message, cause);
    }
}
