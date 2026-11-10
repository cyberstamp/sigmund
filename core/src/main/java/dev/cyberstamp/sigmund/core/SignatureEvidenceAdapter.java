package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Bridges Layer 2 (signature operations) to Layer 1 (identity verification).
 * <p>
 * Wraps a {@link SignatureFormat} and its associated {@link SignatureTool}s into an
 * {@link EvidenceProvider}. There is one adapter per format, not per tool — the adapter
 * parses the file once and routes each {@link Claim} to the right tool via
 * {@link SignatureTool#canVerify(Claim)}.
 *
 * <h2>Verification flow</h2>
 * <ol>
 * <li>{@link SignatureFormat#canHandle(Evidence)} → detection</li>
 * <li>{@link SignatureFormat#parse(Evidence)} → {@link Claim}s</li>
 * <li>Each claim routed through the tools by {@link ClaimRouter} → the {@link ClaimResult} of
 * the answer that counts, with the credentials its tool says it proved</li>
 * </ol>
 *
 * <h2>Key fetching</h2>
 * <p>
 * Each tool owns its key fetching configuration (keyservers, persistence mode,
 * circuit breaker). The adapter simply asks the verifying tool to fetch a missing
 * key via {@link KeyImporter#fetchKey(String)}.
 *
 * @see EvidenceProvider
 * @see SignatureFormat
 * @see SignatureTool
 */
class SignatureEvidenceAdapter implements EvidenceProvider {

    private final SignatureFormat format;
    private final List<SignatureTool> tools;
    private final ClaimRouter router;

    /**
     * Creates a new adapter bridging the given format and tools into an evidence provider.
     *
     * @param format the signature format (e.g., {@link OpenPgpSignatureFormat})
     * @param tools the tools that can verify claims of this format
     */
    public SignatureEvidenceAdapter(SignatureFormat format, List<SignatureTool> tools) {
        this.format = format;
        this.tools = List.copyOf(tools);
        this.router = new ClaimRouter(this.tools);
    }

    /**
     * {@inheritDoc}
     *
     * @return the name of the underlying {@link SignatureFormat}
     */
    @Override
    public String name() {
        return format.name();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns {@code true} if at least one of the registered {@link SignatureTool}s
     * is available on the current system.
     */
    @Override
    public boolean isAvailable() {
        return tools.stream().anyMatch(SignatureTool::isAvailable);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates to the underlying {@link SignatureFormat#canHandle(Evidence)}.
     */
    @Override
    public boolean canHandle(Evidence evidence) {
        return format.canHandle(evidence);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Parses the evidence file into claims, verifies each claim with
     * the appropriate tool, optionally fetches missing keys, and wraps results
     * into {@link ClaimResult}s.
     */
    @Override
    public List<ClaimResult> verify(Path artifactFile, Evidence evidence) {
        EvidenceRef ref = evidence.ref();
        List<Claim> claims = parseClaims(evidence);
        List<ClaimResult> results = new ArrayList<>(claims.size());
        for (Claim claim : claims) {
            results.add(router.route(artifactFile, claim, name(), ref));
        }
        return results;
    }

    /**
     * Parses the evidence into individual claims using the underlying format.
     *
     * @param evidence the evidence, already read
     * @return the parsed claims
     */
    private List<Claim> parseClaims(Evidence evidence) {
        return format.parse(evidence);
    }
}
