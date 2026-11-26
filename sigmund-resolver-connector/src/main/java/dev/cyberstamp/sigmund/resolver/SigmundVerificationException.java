package dev.cyberstamp.sigmund.resolver;

import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.transfer.ArtifactTransferException;

/**
 * An artifact did not pass Sigmund verification, or its signatures could not be fetched to verify it. Set on the
 * download of an artifact the connector blocks, or added to the result of a cached artifact the post-processor
 * blocks.
 */
public class SigmundVerificationException extends ArtifactTransferException {

    /**
     * Creates the exception for an artifact the policy blocks.
     *
     * @param artifact the artifact that failed verification
     * @param repository the repository it was downloaded from, or {@code null} when not known
     * @param message the description of the verification result
     */
    public SigmundVerificationException(Artifact artifact, RemoteRepository repository, String message) {
        super(artifact, repository, message);
    }

    /**
     * Creates the exception for an artifact that could not be verified because of an underlying failure.
     *
     * @param artifact the artifact that could not be verified
     * @param repository the repository it was downloaded from, or {@code null} when not known
     * @param message what went wrong
     * @param cause the underlying failure, such as a signature transfer error
     */
    public SigmundVerificationException(
            Artifact artifact, RemoteRepository repository, String message, Throwable cause) {
        super(artifact, repository, message, cause);
    }
}
