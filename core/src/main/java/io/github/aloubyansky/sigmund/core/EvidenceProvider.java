package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.List;

/**
 * The general interface for anything that can verify evidence of identity.
 * <p>
 * This is the Layer 1 (identity verification) interface — it takes a file and returns
 * proven credentials via {@link EvidenceResult}. It operates at a higher level than
 * the Layer 2 {@code SignatureTool} interface, which works with parsed
 * {@code VerificationUnit}s.
 *
 * <h3>Implementations</h3>
 * <ul>
 * <li><strong>Signature evidence</strong> — a {@code SignatureEvidenceAdapter} bridges
 * a {@code SignatureFormat} and its associated {@code SignatureTool}s into an
 * {@code EvidenceProvider}. There is one adapter per format (not per tool).</li>
 * <li><strong>Non-signature evidence</strong> (future) — SLSA provenance attestations,
 * SBOM verification, etc. implement this interface directly.</li>
 * </ul>
 *
 * @see EvidenceResult
 */
public interface EvidenceProvider {

    /**
     * Returns the name of this evidence provider.
     *
     * @return the provider name (e.g., {@code "openpgp"}, {@code "sigstore"})
     */
    String name();

    /**
     * Checks whether this provider is available on the current system.
     *
     * @return {@code true} if the provider can be used
     */
    boolean isAvailable();

    /**
     * Checks whether this provider can handle the given evidence file.
     * <p>
     * Detection is content-based (not just by file extension) where possible.
     *
     * @param evidenceFile the path to the evidence file
     * @return {@code true} if this provider can verify the file
     */
    boolean canHandle(Path evidenceFile);

    /**
     * Verifies evidence and returns results with proven credentials.
     * <p>
     * A single evidence file may produce multiple results — for example, an OpenPGP
     * signature file with two armored blocks produces two results (one per block).
     *
     * @param artifactFile the artifact that was signed
     * @param evidenceFile the evidence file to verify
     * @return the verification results with proven credentials
     * @throws ToolExecutionException if verification cannot be attempted due to
     *         infrastructure failure
     */
    List<EvidenceResult> verify(Path artifactFile, Path evidenceFile);
}
