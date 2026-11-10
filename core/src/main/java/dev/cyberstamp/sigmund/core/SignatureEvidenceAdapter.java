package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.time.Instant;
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
 * <li>Each claim routed through the tools by {@link ClaimRouter} → the {@link VerifyResult}
 * that counts</li>
 * <li>{@link SignatureTool#extractCredentials(VerifyResult)} → proven credentials</li>
 * <li>Wrap into {@link ClaimResult}</li>
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
            results.add(verifyClaim(artifactFile, claim, ref));
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

    /**
     * Verifies a single claim against the artifact file.
     * <p>
     * The toolchain is asked as {@link ClaimRouter} describes; the answer that counts is
     * recorded with the credentials its tool says it proved, and a tool that broke or a claim no
     * tool could check is recorded with none.
     *
     * @param artifactFile the artifact whose signature is being verified
     * @param claim the claim to verify
     * @return the evidence result for this claim
     */
    private ClaimResult verifyClaim(Path artifactFile, Claim claim, EvidenceRef ref) {
        return router.route(artifactFile, claim, new ClaimRouter.Recorder<>() {
            @Override
            public ClaimResult answered(SignatureTool tool, VerifyResult result) {
                return asClaimResult(tool, claim, result, ref);
            }

            @Override
            public ClaimResult broke(SignatureTool tool, VerifyResult result) {
                return ClaimResult.of(claim, name(), result, List.of(), ref,
                        TrustRootRef.unknown(), tool.name(), Instant.now());
            }

            @Override
            public ClaimResult unanswered(VerifyResult result) {
                return ClaimResult.of(claim, name(), result, List.of(), ref,
                        TrustRootRef.unknown(), null, Instant.now());
            }
        });
    }

    /**
     * Wraps a verification result into an {@link ClaimResult} by extracting
     * proven credentials from the tool.
     *
     * @param tool the tool that performed the verification
     * @param result the verification result to wrap
     * @return the evidence result containing the verification outcome and extracted credentials
     */
    private ClaimResult asClaimResult(SignatureTool tool, Claim claim, VerifyResult result,
            EvidenceRef ref) {
        return ClaimResult.of(claim, name(), result, tool.extractCredentials(result), ref,
                trustRootOf(tool, result), tool.name(), Instant.now());
    }

    /**
     * Names the trust root a claim was verified against: the source of the very key when the
     * tool reports it, otherwise the tool's own trust root.
     */
    private static TrustRootRef trustRootOf(SignatureTool tool, VerifyResult result) {
        return result instanceof OpenPgpVerifyResult openPgp && openPgp.keySource() != null
                ? openPgp.keySource()
                : tool.trustRoot();
    }
}
