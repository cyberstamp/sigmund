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
 * <li>For each claim, find a {@link SignatureTool} where {@code canVerify(claim)} is true</li>
 * <li>{@link SignatureTool#verify(Path, Claim)} → {@link VerifyResult}</li>
 * <li>If the key is unavailable, ask the tool to fetch it (when it implements
 * {@link KeyImporter}) and re-verify; if it is still unavailable, continue to the next
 * tool</li>
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

    /**
     * Creates a new adapter bridging the given format and tools into an evidence provider.
     *
     * @param format the signature format (e.g., {@link OpenPgpSignatureFormat})
     * @param tools the tools that can verify claims of this format
     */
    public SignatureEvidenceAdapter(SignatureFormat format, List<SignatureTool> tools) {
        this.format = format;
        this.tools = List.copyOf(tools);
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
     * Routes the claim to each tool in priority order. If a tool returns
     * {@link IndeterminateReason#KEY_UNAVAILABLE} and implements {@link KeyImporter}, the
     * adapter asks it to fetch the key and re-verifies. Only
     * {@link ClaimOutcome#VERIFIED} stops iteration immediately; other outcomes fall
     * through to the next tool, keeping the most conclusive answer seen
     * ({@link VerifyResult#isMoreConclusiveThan}).
     *
     * @param artifactFile the artifact whose signature is being verified
     * @param claim the claim to verify
     * @return the evidence result for this claim
     */
    private ClaimResult verifyClaim(Path artifactFile, Claim claim, EvidenceRef ref) {
        ClaimResult best = null;
        VerifyResult bestResult = null;
        for (SignatureTool tool : tools) {
            VerifyResult result;
            try {
                if (!tool.canVerify(claim)) {
                    continue;
                }
                result = tool.verify(artifactFile, claim);
                if (result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)) {
                    continue;
                }
                if (result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)) {
                    result = fetchKeyAndRetry(artifactFile, claim, tool, result);
                }
                if (result.isVerified()) {
                    return asClaimResult(tool, claim, result, ref);
                }
                if (bestResult == null || result.isMoreConclusiveThan(bestResult)) {
                    bestResult = result;
                    best = asClaimResult(tool, claim, result, ref);
                }
            } catch (RuntimeException e) {
                // A tool that breaks is one tool's failure, not the run's: the claim records
                // that nothing could check it, the remaining tools still get their turn, and
                // an operator reads the reason from the report rather than a stack trace.
                result = toolFailure(tool, e);
                if (bestResult == null || result.isMoreConclusiveThan(bestResult)) {
                    bestResult = result;
                    best = ClaimResult.of(claim, name(), result, List.of(), ref,
                            TrustRootRef.unknown(), tool.name(), Instant.now());
                }
            }
        }
        if (best != null) {
            return best;
        }
        return ClaimResult.of(claim, name(),
                new UnverifiedResult(ClaimOutcome.INDETERMINATE,
                        IndeterminateReason.UNSUPPORTED_ALGORITHM),
                List.of(), ref, TrustRootRef.unknown(), null, Instant.now());
    }

    /**
     * Records a tool that threw as a claim nothing could check.
     *
     * <p>
     * The exception is logged because {@link IndeterminateReason#TOOL_UNAVAILABLE} says only
     * that the tool could not be run, not why; without the log the cause would be lost.
     *
     * @param tool the tool that threw
     * @param failure what it threw
     * @return an indeterminate result citing {@link IndeterminateReason#TOOL_UNAVAILABLE}
     */
    private VerifyResult toolFailure(SignatureTool tool, RuntimeException failure) {
        System.getLogger(SignatureEvidenceAdapter.class.getName())
                .log(System.Logger.Level.WARNING,
                        "Verification tool '" + tool.name() + "' failed; recording the claim as "
                                + "indeterminate",
                        failure);
        return new UnverifiedResult(ClaimOutcome.INDETERMINATE,
                IndeterminateReason.TOOL_UNAVAILABLE);
    }

    /**
     * Attempts to fetch a missing key and re-verify with the same tool.
     * <p>
     * If the tool implements {@link KeyImporter}, asks it to fetch the key.
     * The tool handles keyserver iteration, circuit breaking, and persistence
     * internally. If the key is fetched, re-verifies with the same tool.
     *
     * @param artifactFile the artifact being verified
     * @param claim the claim whose key is missing
     * @param tool the tool to retry verification with
     * @param originalResult the result citing {@link IndeterminateReason#KEY_UNAVAILABLE}
     * @return the result of re-verification after import, or the original result if fetching failed
     */
    private VerifyResult fetchKeyAndRetry(Path artifactFile, Claim claim,
            SignatureTool tool, VerifyResult originalResult) {
        String keyId = extractKeyIdFromClaim(claim);
        if (keyId == null) {
            return originalResult;
        }

        if (tool instanceof KeyImporter ki && ki.fetchKey(keyId)) {
            return tool.verify(artifactFile, claim);
        }
        return originalResult;
    }

    /**
     * Extracts the key ID (fingerprint) from a claim, if available.
     *
     * @param claim the claim
     * @return the issuer fingerprint for OpenPGP claims, or {@code null} for unsupported claim types
     */
    private String extractKeyIdFromClaim(Claim claim) {
        if (claim instanceof OpenPgpClaim opgu) {
            return opgu.issuerFingerprint();
        }
        return null;
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
                tool.trustRoot(), tool.name(), Instant.now());
    }
}
