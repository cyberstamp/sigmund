package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * The SPI that signing/verification backends implement.
 * <p>
 * A tool is fully configured at construction time — credentials (key IDs, fingerprints,
 * OIDC provider references) are provided when the tool is created. {@link #sign(Path, Path)}
 * takes no credential argument; the tool embodies its context.
 *
 * <h2>Construction-time configuration</h2>
 * <p>
 * {@link #canSign()} returns {@code true} only if signing credentials were provided at
 * construction. A verify-only tool instance has {@code canSign() → false}.
 *
 * <h2>Verification routing</h2>
 * <p>
 * {@link #canVerify(Claim)} lets each tool declare what it can handle within
 * its format. For OpenPGP, GPG handles {@code packetVersion <= 4} and Sequoia handles
 * {@code packetVersion >= 5}. This keeps all routing decisions out of the facade.
 *
 * <h2>Credential extraction and trust boundary</h2>
 * <p>
 * {@link #extractCredentials(VerifyResult)} converts a verification result into proven
 * {@link Credential}s. The credential type is determined by the packet version that was
 * cryptographically verified, not by which tool performed the verification. A signature
 * cannot "claim" a credential type it wasn't verified through.
 *
 * <h2>Concurrency</h2>
 * <p>
 * Implementations must be safe for concurrent use. Since tools are configured at
 * construction and carry no mutable state after that, the Java side is naturally
 * thread-safe. However, CLI tool wrappers must account for underlying tool constraints
 * (e.g., GPG may lock the keyring during concurrent operations).
 *
 * @see SignatureFormat
 * @see Claim
 * @see VerifyResult
 */
public interface SignatureTool {

    /**
     * Returns the tool name.
     *
     * @return the name (e.g., {@code "gpg"}, {@code "sq"}, {@code "sigstore"})
     */
    String name();

    /**
     * Checks whether this tool is available on the current system.
     *
     * @return {@code true} if the tool can be used
     */
    boolean isAvailable();

    /**
     * Checks whether this tool has signing credentials configured.
     *
     * @return {@code true} if signing is available
     */
    boolean canSign();

    /**
     * Returns information about the signing identities this tool will use.
     * <p>
     * Returns an empty list if no signing credentials are configured
     * ({@link #canSign()} is {@code false}).
     *
     * @return signing identity information, one entry per signing key
     */
    default List<SigningInfo> signingInfo() {
        return List.of();
    }

    /**
     * Returns the signature format this tool produces and consumes.
     *
     * @return the signature format
     */
    SignatureFormat signatureFormat();

    /**
     * Returns the credential types this tool can sign with.
     * <p>
     * This is a <strong>capability</strong> declaration — it says what the tool <em>can</em> do,
     * not what it <em>will</em> do in a given configuration. Used by the builder to route
     * signer credentials to tools for signing. Not used for verification —
     * {@link #canVerify(Claim)} handles that based on claim content.
     *
     * @return the supported credential type strings
     *         (e.g., {@code ["openpgp4"]}, {@code ["openpgp4", "openpgp6"]})
     */
    Set<String> supportedCredentialTypes();

    /**
     * Checks whether this tool can verify the given claim.
     * <p>
     * For OpenPGP, routing is based on the signature packet version: GPG handles
     * v1–v4, Sequoia handles v5+. For Sigstore, the tool handles its own claim type.
     *
     * @param claim the claim to check
     * @return {@code true} if this tool can verify the claim
     */
    boolean canVerify(Claim claim);

    /**
     * Returns the trust root this tool verifies against.
     *
     * <p>
     * The root is a property of how the tool was configured, not of an individual claim, so
     * it is reported once rather than per result. Recording it is what lets two runs that
     * disagree about the same artifact be told apart: one machine's keyring held the signer's
     * key, another's did not.
     *
     * @return the trust root, or {@link TrustRootRef#unknown()} when the tool cannot say
     */
    default TrustRootRef trustRoot() {
        return TrustRootRef.unknown();
    }

    /**
     * Signs an artifact file and writes the signature to the output path.
     * <p>
     * The signing credential is embedded in the tool at construction time.
     * This method may perform network access or require user interaction
     * (e.g., Sigstore OIDC authentication).
     *
     * @param artifactFile the file to sign
     * @param outputSig the path to write the signature file
     * @return the signing result with algorithm metadata
     * @throws ToolExecutionException if signing fails due to infrastructure error
     * @throws IllegalStateException if {@link #canSign()} is {@code false}
     */
    SignResult sign(Path artifactFile, Path outputSig);

    /**
     * Verifies a single claim against an artifact file.
     * <p>
     * Returns a result object, never throws for verification outcomes (invalid signature,
     * missing key). Throws only for infrastructure failures.
     *
     * @param artifactFile the artifact that was signed
     * @param claim the claim to verify
     * @return the typed verification result
     * @throws ToolExecutionException if verification cannot be attempted
     */
    VerifyResult verify(Path artifactFile, Claim claim);

    /**
     * Extracts proven credentials from a verification result.
     * <p>
     * The tool knows what credentials its results prove. For OpenPGP tools, this maps
     * the verified packet version to the credential type:
     * {@code version < 6} → {@code FingerprintCredential("openpgp4", ...)},
     * {@code version >= 6} → {@code FingerprintCredential("openpgp6", ...)}.
     * <p>
     * Returns an empty list unless the result is {@link ClaimOutcome#VERIFIED}: an
     * unverified claim proves no credential.
     *
     * @param result the verification result to extract credentials from
     * @return the proven credentials, or an empty list if verification did not pass
     */
    List<Credential> extractCredentials(VerifyResult result);
}
