package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * The SPI that signing/verification backends implement.
 * <p>
 * A tool is fully configured at construction time — credentials (key IDs, fingerprints,
 * OIDC provider references) are provided when the tool is created. The keys it signs with are
 * the ones {@link #signingInfo()} reports, and {@link #sign(Path, Path, SigningInfo)} is called
 * once per key with one of those entries.
 *
 * <h2>Construction-time configuration</h2>
 * <p>
 * {@link #canSign()} returns {@code true} only if signing credentials were provided at
 * construction. A verify-only tool instance has {@code canSign() → false}.
 *
 * <h2>Verification routing</h2>
 * <p>
 * {@link #canVerify(Claim)} lets each tool declare what it can handle within
 * its format. For OpenPGP, GPG handles {@code packetVersion <= 4} and Sequoia handles the
 * RFC 9580 versions, 4 and 6; no backend takes LibrePGP's version 5. This keeps all routing
 * decisions out of the facade.
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
     * Returns information about the signing keys this tool will use.
     * <p>
     * Returns an empty list if no signing credentials are configured
     * ({@link #canSign()} is {@code false}). A tool whose {@link #canSign()} is {@code true}
     * returns one entry per key it signs with and never an empty list: a key that cannot be
     * read still gets an entry, with a {@code null} credential type. Each entry's
     * {@linkplain SigningInfo#toolName() tool name} is this tool's {@link #name()}: signing gives
     * the key back to the tool of that name.
     * <p>
     * The default returns an empty list. A signing tool that does not override it is planned as
     * one key of unknown type, which fails any run that requests credential types.
     *
     * @return signing key information, one entry per signing key
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
     * not what it <em>will</em> do in a given configuration. Signing does not select tools
     * or keys through this method: the requested credential types select keys from the types
     * reported by {@link #signingInfo()}, in the signing plan. Not used for verification —
     * {@link #canVerify(Claim)} handles that based on claim content.
     *
     * @return the supported credential type strings
     *         (e.g., {@code ["pgp4"]}, {@code ["pgp4", "pgp6"]})
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
     * Signs an artifact file with one key and writes the signature to the output path.
     * <p>
     * The key is one of the entries {@link #signingInfo()} returned; a tool reporting no
     * entry is given one carrying only its name. The signing credential behind the key is
     * embedded in the tool at construction time: the entry selects it, it does not supply it. A
     * tool with a single credential, such as a TSK file, a key from the environment or a
     * Sigstore identity, signs with that credential whatever the entry names.
     * <p>
     * This method may perform network access or require user interaction
     * (e.g., Sigstore OIDC authentication).
     *
     * @param artifactFile the file to sign
     * @param outputSig the path to write the signature file
     * @param key the key to sign with, one of this tool's {@link #signingInfo()} entries
     * @return the signing result with algorithm metadata
     * @throws ToolExecutionException if signing fails due to infrastructure error
     * @throws IllegalStateException if {@link #canSign()} is {@code false}
     * @throws IllegalArgumentException if the tool cannot sign with the given key; the message
     *         names the tool and the key's fingerprint
     */
    SignResult sign(Path artifactFile, Path outputSig, SigningInfo key);

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
     * {@code version < 6} → {@code KeyCredential("pgp4", ...)},
     * {@code version >= 6} → {@code KeyCredential("pgp6", ...)}.
     * <p>
     * Returns an empty list unless the result is {@link ClaimOutcome#VERIFIED}: an
     * unverified claim proves no credential.
     *
     * @param result the verification result to extract credentials from
     * @return the proven credentials, or an empty list if verification did not pass
     */
    List<Credential> extractCredentials(VerifyResult result);
}
