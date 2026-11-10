package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.List;

/**
 * Routes a {@link Claim} through the toolchain and keeps the answer that counts.
 *
 * <p>
 * The one place that decides which tool's answer stands for a claim, used both by trust
 * verification ({@link SignatureEvidenceAdapter}) and by direct signature verification
 * ({@link Sigmund#verify(Path, Path)}), so that the two cannot disagree about a claim:
 * <ul>
 * <li>Tools are asked in toolchain order; a tool whose {@link SignatureTool#canVerify(Claim)}
 * declines is not asked.</li>
 * <li>{@link IndeterminateReason#UNSUPPORTED_ALGORITHM} from a tool passes the claim on to the
 * next tool without being kept.</li>
 * <li>{@link IndeterminateReason#KEY_UNAVAILABLE} from a tool that is a {@link KeyImporter}
 * makes it fetch the key, and the tool is asked again.</li>
 * <li>A conclusive answer — {@link ClaimOutcome#VERIFIED} or {@link ClaimOutcome#FAILED} — ends
 * the routing and stands. A later tool is never asked to overrule it: the bytes match or they
 * do not whichever tool checks, so the toolchain order decides only who answers, never what
 * the answer is, and a {@code FAILED} attack signal cannot be outvoted.</li>
 * <li>An indeterminate answer passes the claim on, so that a tool with a different key store
 * can still decide it; the most conclusive indeterminate answer seen is kept
 * ({@link VerifyResult#isMoreConclusiveThan}).</li>
 * <li>A tool that throws is recorded as {@link IndeterminateReason#TOOL_UNAVAILABLE}, and the
 * remaining tools still get their turn.</li>
 * <li>A claim no tool answered is {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}, with
 * what the claim reveals of its algorithm and key: every claim is answered, so a block nobody
 * could check is never left out of a result.</li>
 * </ul>
 */
final class ClaimRouter {

    /**
     * Turns the answer for a claim into what the caller keeps.
     *
     * @param <T> what the caller records per claim
     */
    interface Recorder<T> {

        /**
         * Records a tool's answer. Runs while the tool still has its turn: if it throws, the
         * tool is treated as having broken, as if {@link SignatureTool#verify} had thrown.
         *
         * @param tool the tool that answered
         * @param result its answer
         * @return the record
         */
        T answered(SignatureTool tool, VerifyResult result);

        /**
         * Records a tool that threw.
         *
         * @param tool the tool that threw
         * @param result the answer standing for it, citing
         *        {@link IndeterminateReason#TOOL_UNAVAILABLE}
         * @return the record
         */
        T broke(SignatureTool tool, VerifyResult result);

        /**
         * Records a claim no tool answered.
         *
         * @param result the answer standing for it, citing
         *        {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}
         * @return the record
         */
        T unanswered(VerifyResult result);
    }

    private final List<SignatureTool> tools;

    /**
     * Creates a router over the given toolchain.
     *
     * @param tools the tools, in the order they are asked
     */
    ClaimRouter(List<SignatureTool> tools) {
        this.tools = List.copyOf(tools);
    }

    /**
     * Routes a claim through the toolchain.
     *
     * @param artifactFile the artifact the claim is about
     * @param claim the claim
     * @param recorder how the caller records the answer
     * @param <T> what the caller records
     * @return the record of the answer that counts; never {@code null}
     */
    <T> T route(Path artifactFile, Claim claim, Recorder<T> recorder) {
        T best = null;
        VerifyResult bestResult = null;
        for (SignatureTool tool : tools) {
            VerifyResult result;
            T record;
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
                record = recorder.answered(tool, result);
            } catch (RuntimeException e) {
                // A tool that breaks is one tool's failure, not the run's: the claim records
                // that nothing could check it, the remaining tools still get their turn, and
                // an operator reads the reason from the report rather than a stack trace.
                result = toolFailure(tool, e);
                record = recorder.broke(tool, result);
            }
            if (result.isVerified() || result.isFailed()) {
                return record;
            }
            if (bestResult == null || result.isMoreConclusiveThan(bestResult)) {
                bestResult = result;
                best = record;
            }
        }
        if (best != null) {
            return best;
        }
        return recorder.unanswered(unanswered(claim));
    }

    /**
     * The answer standing for a claim no tool answered, keeping what the claim itself reveals:
     * for an OpenPGP signature, its algorithm and the key it names, so the report says which
     * block went unchecked and whose key it would need. The key stays unproven.
     *
     * @param claim the claim no tool answered
     * @return an indeterminate result citing {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}
     */
    private static VerifyResult unanswered(Claim claim) {
        if (claim instanceof OpenPgpClaim openPgp) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM,
                    null, Algorithms.algorithmName(openPgp.algorithmId()),
                    openPgp.packetVersion(), openPgp.issuerFingerprint(), null);
        }
        return new UnverifiedResult(ClaimOutcome.INDETERMINATE,
                IndeterminateReason.UNSUPPORTED_ALGORITHM);
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
    private static VerifyResult toolFailure(SignatureTool tool, RuntimeException failure) {
        System.getLogger(ClaimRouter.class.getName())
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
    private static VerifyResult fetchKeyAndRetry(Path artifactFile, Claim claim,
            SignatureTool tool, VerifyResult originalResult) {
        String keyId = claim instanceof OpenPgpClaim openPgp ? openPgp.issuerFingerprint() : null;
        if (keyId == null) {
            return originalResult;
        }
        if (tool instanceof KeyImporter ki && ki.fetchKey(keyId)) {
            return tool.verify(artifactFile, claim);
        }
        return originalResult;
    }
}
