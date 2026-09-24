package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What a verification run found, grouped for reporting, and which of it blocks the build.
 *
 * <p>
 * This lives in core rather than in an integration so that every insertion point says the
 * same thing about the same evidence. A goal and a resolver-level extension that
 * disagreed about which artifacts block, or described the same outcome differently, would
 * undermine the claim that they verify alike.
 *
 * <p>
 * Presentation is left to the caller: this decides what to say and what it means, not how to
 * render it. A build tool logs at its own severities, a CLI prints, an attestation serializes.
 */
public final class VerificationReport {

    private final Map<ArtifactOutcome, List<ArtifactResult>> byOutcome;
    private final Map<ArtifactOutcome, Integer> counts;
    private final TrustPolicy policy;

    private VerificationReport(Map<ArtifactOutcome, List<ArtifactResult>> byOutcome,
            Map<ArtifactOutcome, Integer> counts, TrustPolicy policy) {
        this.byOutcome = byOutcome;
        this.counts = counts;
        this.policy = policy;
    }

    /**
     * Collects the results of a run.
     *
     * @param results one result per artifact assessed
     * @param policy the policy the run applied, which decides what blocks
     * @return the report
     */
    public static VerificationReport of(List<ArtifactResult> results, TrustPolicy policy) {
        Map<ArtifactOutcome, List<ArtifactResult>> grouped = new EnumMap<>(ArtifactOutcome.class);
        for (ArtifactResult result : results) {
            grouped.computeIfAbsent(result.outcome(), outcome -> new ArrayList<>()).add(result);
        }

        // Wrapped rather than copied with Map.copyOf: that returns an unordered map, and a
        // report whose sections appear in a different order each run is harder to read and to
        // diff. An EnumMap orders by the outcome vocabulary itself.
        Map<ArtifactOutcome, List<ArtifactResult>> byOutcome = new EnumMap<>(ArtifactOutcome.class);
        Map<ArtifactOutcome, Integer> counts = new EnumMap<>(ArtifactOutcome.class);
        grouped.forEach((outcome, group) -> {
            byOutcome.put(outcome, List.copyOf(group));
            counts.put(outcome, group.size());
        });
        return new VerificationReport(Collections.unmodifiableMap(byOutcome),
                Collections.unmodifiableMap(counts), policy);
    }

    /**
     * Returns the results grouped by outcome, in the outcome vocabulary's own order, so that
     * two runs of the same build produce reports that read and diff the same way.
     *
     * @return an unmodifiable view, omitting outcomes nothing reached
     */
    public Map<ArtifactOutcome, List<ArtifactResult>> byOutcome() {
        return byOutcome;
    }

    /**
     * Returns how many artifacts reached each outcome.
     *
     * <p>
     * Only outcomes that occurred appear. Coverage counts (§2.1) are built from these, and a
     * zero entry for an outcome nothing reached would misrepresent what the run examined.
     *
     * @return counts by outcome
     */
    public Map<ArtifactOutcome, Integer> counts() {
        return counts;
    }

    /**
     * Returns the artifacts whose outcome the policy does not tolerate.
     *
     * <p>
     * {@link ArtifactOutcome#FAILED} always blocks: a signature that does not verify is an
     * attack signal, not a coverage question, and no setting overrides it — including for an
     * artifact the policy allows to carry no signature at all. Missing evidence blocks unless
     * the policy tolerates it for that artifact, and an artifact no rule covers never blocks,
     * because policy is silent about it rather than permissive.
     *
     * @return the blocking results, in the order they were assessed
     */
    public List<ArtifactResult> blocking() {
        List<ArtifactResult> blocking = new ArrayList<>();
        byOutcome.forEach((outcome, results) -> {
            for (ArtifactResult result : results) {
                if (blocks(outcome, result)) {
                    blocking.add(result);
                }
            }
        });
        return List.copyOf(blocking);
    }

    private boolean blocks(ArtifactOutcome outcome, ArtifactResult result) {
        return switch (outcome) {
            case FAILED -> true;
            case UNSATISFIED, INDETERMINATE -> policy.onUntrusted() == UntrustedPolicy.FAIL;
            case NO_CLAIM -> policy.onUntrusted() == UntrustedPolicy.FAIL
                    && !policy.isUnsignedAllowed(result.subject().coords());
            case SATISFIED, NOT_CONFIGURED -> false;
        };
    }

    /**
     * Artifacts that were attested alike, and what they share.
     *
     * <p>
     * A report that repeated the signer, the tool and the trust root on every one of two
     * hundred dependency lines buries the few lines that differ. Said once per group, what
     * varies per artifact is what remains.
     *
     * @param summary one line per claim naming who attested and how, empty when nothing
     *        attested these artifacts
     * @param detail what that attestation proved and what it was checked against, indented
     *        under the summary; empty when the claims recorded neither
     * @param artifacts the artifacts, in coordinate order
     */
    public record AttesterGroup(List<String> summary, List<String> detail,
            List<ArtifactResult> artifacts) {
    }

    /**
     * Groups results by what attested them.
     *
     * <p>
     * Two artifacts share a group when their claims proved the same credentials, through the
     * same tool, against the same trust root. Proven credentials are the key, not the display
     * name a key carries: the same name over two different keys is a rotation or an
     * impersonation, and a report that merged them would show neither. Artifacts nothing
     * attested form a final group with no summary.
     *
     * @param results the results to group, typically one outcome's worth
     * @return the groups, ordered the same way for the same results
     */
    public static List<AttesterGroup> groupByAttester(List<ArtifactResult> results) {
        Map<List<String>, List<ArtifactResult>> grouped = new LinkedHashMap<>();
        for (ArtifactResult result : results) {
            grouped.computeIfAbsent(attesterKey(result), key -> new ArrayList<>()).add(result);
        }

        List<List<String>> keys = new ArrayList<>(grouped.keySet());
        // unattributed last: the artifacts nothing claimed are the ones an operator acts on,
        // and they read as a closing section rather than as a nameless block among signers
        keys.sort(Comparator.<List<String>, Boolean> comparing(List::isEmpty)
                .thenComparing(key -> String.join("\n", key)));

        List<AttesterGroup> groups = new ArrayList<>(keys.size());
        for (List<String> key : keys) {
            List<ArtifactResult> artifacts = new ArrayList<>(grouped.get(key));
            artifacts.sort(Comparator.comparing(result -> result.subject().coords()));
            ClaimResult[] claims = artifacts.get(0).claims().toArray(new ClaimResult[0]);
            groups.add(new AttesterGroup(summaryOf(claims), detailOf(claims),
                    List.copyOf(artifacts)));
        }
        return List.copyOf(groups);
    }

    /**
     * Builds the grouping key: everything the artifacts of a group must share.
     */
    private static List<String> attesterKey(ArtifactResult result) {
        ClaimResult[] claims = result.claims().toArray(new ClaimResult[0]);
        List<String> key = new ArrayList<>(summaryOf(claims));
        key.addAll(detailOf(claims));
        return List.copyOf(key);
    }

    private static List<String> summaryOf(ClaimResult[] claims) {
        List<String> summary = new ArrayList<>(claims.length);
        for (ClaimResult claim : claims) {
            summary.add(headline(claim));
        }
        return List.copyOf(summary);
    }

    private static List<String> detailOf(ClaimResult[] claims) {
        List<String> detail = new ArrayList<>();
        for (ClaimResult claim : claims) {
            for (Credential credential : claim.attesterCredentials()) {
                detail.add("  credential " + credential.type() + " " + credential.displayName());
            }
            TrustRootRef trustRoot = claim.trustRoot();
            if (trustRoot != null && trustRoot.identifier() != null) {
                detail.add("  trust root " + trustRoot.kind() + " " + trustRoot.identifier());
            }
        }
        return List.copyOf(detail);
    }

    /**
     * Explains one artifact: the evidence each claim was read from, and when it was made.
     *
     * <p>
     * Who attested and against what is said once by the artifact's group; this carries only
     * what differs artifact by artifact. Only what a claim actually recorded appears, so a
     * sparse block means the tool said little, not that the report omitted something.
     *
     * @param result the result to explain
     * @return the lines, empty when no claim was found
     */
    public static List<String> explain(ArtifactResult result) {
        List<String> lines = new ArrayList<>();
        for (ClaimResult claim : result.claims()) {
            EvidenceRef evidence = claim.evidence();
            lines.add("evidence " + evidence.file().getFileName()
                    + " sha256:" + shorten(evidence.digest().sha256())
                    + " (" + evidence.source() + ")");
            if (claim.claimTime() != null) {
                lines.add("claimed " + claim.claimTime() + " ("
                        + claim.claimTimeSource().name().toLowerCase() + ")");
            }
        }
        return List.copyOf(lines);
    }

    /**
     * Builds a claim's first line: the outcome, the tool that reached it, and who it names.
     */
    private static String headline(ClaimResult claim) {
        StringBuilder headline = new StringBuilder(claim.kind()).append(' ')
                .append(claim.outcome());
        if (claim.reason() != null) {
            headline.append(" (").append(claim.reason()).append(')');
        }
        if (claim.verifiedBy() != null) {
            headline.append(" by ").append(claim.verifiedBy());
        }
        if (claim.algorithm() != null) {
            headline.append(" (").append(claim.algorithm()).append(')');
        }
        if (claim.attesterDisplayName() != null) {
            headline.append(" - ").append(claim.attesterDisplayName());
        }
        if (claim.role() != AttesterRole.UNKNOWN) {
            headline.append(" [").append(claim.role().name().toLowerCase()).append(']');
        }
        return headline.toString();
    }

    /**
     * Shortens a digest to what a human compares by eye; the full value belongs in a
     * serialized result.
     */
    private static String shorten(String digest) {
        return digest.length() > 12 ? digest.substring(0, 12) : digest;
    }
}
