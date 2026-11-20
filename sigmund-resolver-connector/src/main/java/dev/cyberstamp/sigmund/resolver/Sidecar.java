package dev.cyberstamp.sigmund.resolver;

import static java.util.Objects.requireNonNull;

import java.nio.file.Path;
import org.eclipse.aether.artifact.Artifact;

/**
 * What became of one signature file of an artifact: found at a path, missing, or not obtained because of a
 * failure. A missing signature is no claim, which the policy judges; a failure fails the artifact, so a network
 * fault cannot turn a required signature into "unsigned".
 *
 * @param signature the signature artifact, such as {@code lib-1.0.jar.asc}
 * @param path the signature file, or {@code null} when it was not found
 * @param failure why it could not be obtained, or {@code null} when it was found or is missing
 */
public record Sidecar(Artifact signature, Path path, Exception failure) {

    /**
     * Creates a sidecar, checking that at most one of {@code path} and {@code failure} is set.
     */
    public Sidecar {
        requireNonNull(signature);
        if (path != null && failure != null) {
            throw new IllegalArgumentException("a sidecar is found or failed, not both");
        }
    }

    /**
     * A signature file that was found.
     *
     * @param signature the signature artifact
     * @param path its file
     * @return the sidecar
     */
    public static Sidecar found(Artifact signature, Path path) {
        return new Sidecar(signature, requireNonNull(path), null);
    }

    /**
     * A signature file that does not exist.
     *
     * @param signature the signature artifact
     * @return the sidecar
     */
    public static Sidecar missing(Artifact signature) {
        return new Sidecar(signature, null, null);
    }

    /**
     * A signature file that could not be obtained.
     *
     * @param signature the signature artifact
     * @param failure why
     * @return the sidecar
     */
    public static Sidecar failed(Artifact signature, Exception failure) {
        return new Sidecar(signature, null, requireNonNull(failure));
    }
}
