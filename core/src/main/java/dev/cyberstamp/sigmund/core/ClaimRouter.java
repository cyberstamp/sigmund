package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Routes a {@link Claim} through the toolchain and records the answer that counts as its
 * {@link ClaimResult}.
 *
 * <p>
 * The one place that decides which tool's answer stands for a claim, used both by trust
 * verification ({@link SignatureEvidenceAdapter}) and by direct signature verification
 * ({@link Sigmund#verify(Path, Path)}), so that the two cannot disagree about a claim:
 * <ul>
 * <li>An OpenPGP block that holds no signature packet ({@link OpenPgpClaim#holdsSignaturePacket()})
 * — one that cannot be decoded, or whose first packet is not a signature — is
 * {@link IndeterminateReason#EVIDENCE_MALFORMED} and no tool is asked: {@code gpg} and
 * {@code sq} do not take such a block and Bouncy Castle cannot parse it, so it is settled here,
 * where the answer cannot depend on the toolchain.</li>
 * <li>An OpenPGP signature that is not a document signature
 * ({@link OpenPgpClaim#isNonDocumentSignature()}) is
 * {@link IndeterminateReason#EVIDENCE_MALFORMED} and no tool is asked: the backends disagree on
 * such a block — {@code sq} counts it a bad signature, GnuPG an error, Bouncy Castle a key it
 * cannot use — so the answer is settled here, where it cannot depend on the tool.</li>
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
     * Routes a claim through the toolchain and records what it established.
     *
     * <p>
     * Everything asked of a tool happens during its turn: verifying, fetching a missing key,
     * and naming the credentials and trust root of its result. A tool that throws at any of
     * these steps is recorded as having broken, and the next tool gets its turn.
     *
     * @param artifactFile the artifact the claim is about
     * @param claim the claim
     * @param kind the format that produced the claim
     * @param evidence the evidence the claim was parsed from
     * @return the record of the answer that counts; never {@code null}
     */
    ClaimResult route(Path artifactFile, Claim claim, String kind, EvidenceRef evidence) {
        if (claim instanceof OpenPgpClaim openPgp && !openPgp.holdsSignaturePacket()) {
            return ClaimResult.of(claim, kind, notASignature(openPgp), List.of(), evidence,
                    TrustRootRef.unknown(), null, Instant.now());
        }
        if (claim instanceof OpenPgpClaim openPgp && openPgp.isNonDocumentSignature()) {
            return ClaimResult.of(claim, kind, notADocumentSignature(openPgp), List.of(), evidence,
                    TrustRootRef.unknown(), null, Instant.now());
        }
        ClaimResult best = null;
        for (SignatureTool tool : tools) {
            ClaimResult record;
            try {
                if (!tool.canVerify(claim)) {
                    continue;
                }
                VerifyResult result = tool.verify(artifactFile, claim);
                if (result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)) {
                    continue;
                }
                if (result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)) {
                    result = fetchKeyAndRetry(artifactFile, claim, tool, result);
                }
                record = ClaimResult.of(claim, kind, result, tool.extractCredentials(result),
                        evidence, trustRootOf(tool, result), tool.name(), Instant.now());
            } catch (RuntimeException e) {
                // A tool that breaks is one tool's failure, not the run's: the claim records
                // that nothing could check it, the remaining tools still get their turn, and
                // an operator reads the reason from the report rather than a stack trace.
                record = ClaimResult.of(claim, kind, toolFailure(tool, e), List.of(), evidence,
                        TrustRootRef.unknown(), tool.name(), Instant.now());
            }
            VerifyResult result = record.verifyResult();
            if (result.isVerified() || result.isFailed()) {
                return record;
            }
            if (best == null || result.isMoreConclusiveThan(best.verifyResult())) {
                best = record;
            }
        }
        if (best != null) {
            return best;
        }
        return ClaimResult.of(claim, kind, noToolAnswered(claim), List.of(), evidence,
                TrustRootRef.unknown(), null, Instant.now());
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

    /**
     * The result standing for a claim no tool answered, keeping what the claim itself reveals:
     * for an OpenPGP signature, its algorithm and the key it names, so the report says which
     * block went unchecked and whose key it would need. The key stays unproven.
     *
     * @param claim the claim no tool answered
     * @return an indeterminate result citing {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}
     */
    private static VerifyResult noToolAnswered(Claim claim) {
        if (claim instanceof OpenPgpClaim openPgp) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM,
                    null, Algorithms.algorithmName(openPgp.algorithmId()),
                    openPgp.packetVersion(), openPgp.issuerFingerprint(), null);
        }
        return new UnverifiedResult(ClaimOutcome.INDETERMINATE,
                IndeterminateReason.UNSUPPORTED_ALGORITHM);
    }

    /**
     * The result standing for an OpenPGP block that holds no signature packet. The block
     * carries no algorithm or key to name.
     */
    private static VerifyResult notASignature(OpenPgpClaim claim) {
        String detail = claim.packetTag() < 0
                ? "the block cannot be decoded into an OpenPGP packet"
                : String.format("the block holds a packet of tag %d, not a signature", claim.packetTag());
        return OpenPgpVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED, null, null,
                claim.packetVersion(), claim.issuerFingerprint(), null).withDetail(detail);
    }

    /**
     * The result standing for an OpenPGP signature that is not made over a document, keeping
     * its algorithm and the key it names. The key stays unproven.
     */
    private static VerifyResult notADocumentSignature(OpenPgpClaim claim) {
        return OpenPgpVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED, null,
                Algorithms.algorithmName(claim.algorithmId()), claim.packetVersion(),
                claim.issuerFingerprint(), null)
                .withDetail(String.format("a signature of type 0x%02X is not a signature over a document",
                        claim.signatureType()));
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
     * internally. Then re-verifies with the same tool, whether or not the key was fetched:
     * why a fetch failed — keyservers that could not answer — is known only after it, and only a
     * fresh result carries that detail. The cost is one more verification per claim whose key is
     * missing: cheap for Bouncy Castle, one more {@code gpg} process under GnuPG with
     * {@code import-to-keyring}.
     *
     * @param artifactFile the artifact being verified
     * @param claim the claim whose key is missing
     * @param tool the tool to retry verification with
     * @param originalResult the result citing {@link IndeterminateReason#KEY_UNAVAILABLE}
     * @return the result of re-verification after the fetch, or the original result when the
     *         tool cannot fetch or the claim names no fingerprint
     */
    private static VerifyResult fetchKeyAndRetry(Path artifactFile, Claim claim,
            SignatureTool tool, VerifyResult originalResult) {
        String keyId = claim instanceof OpenPgpClaim openPgp ? openPgp.issuerFingerprint() : null;
        if (keyId == null) {
            return originalResult;
        }
        if (tool instanceof KeyImporter importer && importer.canFetchKeys()) {
            importer.fetchKey(keyId);
            return tool.verify(artifactFile, claim);
        }
        return originalResult;
    }
}
