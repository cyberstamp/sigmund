package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Bridges Layer 2 (signature operations) to Layer 1 (identity verification).
 * <p>
 * Wraps a {@link SignatureFormat} and its associated {@link SignatureTool}s into an
 * {@link EvidenceProvider}. There is one adapter per format, not per tool — the adapter
 * parses the file once and routes each {@link VerificationUnit} to the right tool via
 * {@link SignatureTool#canVerify(VerificationUnit)}.
 *
 * <h3>Verification flow</h3>
 * <ol>
 * <li>{@link SignatureFormat#canHandle(Path)} → detection</li>
 * <li>{@link SignatureFormat#parse(Path)} → {@link VerificationUnit}s</li>
 * <li>For each unit, find a {@link SignatureTool} where {@code canVerify(unit)} is true</li>
 * <li>{@link SignatureTool#verify(Path, VerificationUnit)} → {@link VerifyResult}</li>
 * <li>If {@code NO_KEY} and key fetching is enabled, fetch and retry</li>
 * <li>{@link SignatureTool#extractCredentials(VerifyResult)} → proven credentials</li>
 * <li>Wrap into {@link EvidenceResult}</li>
 * </ol>
 *
 * <h3>Key fetching</h3>
 * <p>
 * Key fetching lives in this adapter because it has all the context needed: the
 * {@link VerificationUnit} (with the fingerprint to fetch), the {@link SignatureTool}
 * (to re-verify), and the {@link DiscoveryConfig} (with keyserver and import settings).
 *
 * @see EvidenceProvider
 * @see SignatureFormat
 * @see SignatureTool
 */
public class SignatureEvidenceAdapter implements EvidenceProvider {

    private final SignatureFormat format;
    private final List<SignatureTool> tools;
    private final DiscoveryConfig discoveryConfig;

    /**
     * Creates a new adapter bridging the given format and tools into an evidence provider.
     *
     * @param format the signature format (e.g., {@link OpenPgpSignatureFormat})
     * @param tools the tools that can verify units of this format
     * @param discoveryConfig configuration for key fetching behavior
     */
    public SignatureEvidenceAdapter(SignatureFormat format, List<SignatureTool> tools,
            DiscoveryConfig discoveryConfig) {
        this.format = format;
        this.tools = List.copyOf(tools);
        this.discoveryConfig = discoveryConfig != null ? discoveryConfig : DiscoveryConfig.DEFAULT;
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
     * Delegates to the underlying {@link SignatureFormat#canHandle(Path)}.
     */
    @Override
    public boolean canHandle(Path evidenceFile) {
        return format.canHandle(evidenceFile);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Parses the evidence file into verification units, verifies each unit with
     * the appropriate tool, optionally fetches missing keys, and wraps results
     * into {@link EvidenceResult}s.
     */
    @Override
    public List<EvidenceResult> verify(Path artifactFile, Path evidenceFile) {
        List<VerificationUnit> units = parseUnits(evidenceFile);
        List<EvidenceResult> results = new ArrayList<>(units.size());
        for (VerificationUnit unit : units) {
            results.add(verifyUnit(artifactFile, unit));
        }
        return results;
    }

    /**
     * Parses the evidence file into individual verification units using the underlying format.
     *
     * @param evidenceFile path to the signature/evidence file
     * @return the parsed verification units
     */
    private List<VerificationUnit> parseUnits(Path evidenceFile) {
        return format.parse(evidenceFile);
    }

    /**
     * Verifies a single verification unit against the artifact file.
     * <p>
     * Routes the unit to the appropriate tool, performs verification,
     * attempts key fetching on {@link Verdict#NO_KEY}, and wraps
     * the result as an {@link EvidenceResult}.
     *
     * @param artifactFile the artifact whose signature is being verified
     * @param unit the verification unit to verify
     * @return the evidence result for this unit
     */
    private EvidenceResult verifyUnit(Path artifactFile, VerificationUnit unit) {
        SignatureTool tool = routeUnitToTool(unit);
        if (tool == null) {
            return new EvidenceResult(new UnverifiedResult(Verdict.SKIPPED), List.of(), name());
        }

        VerifyResult result = tool.verify(artifactFile, unit);

        if (result.verdict() == Verdict.NO_KEY) {
            result = fetchKeyAndRetry(artifactFile, unit, tool, result);
        }

        return wrapAsEvidence(tool, result);
    }

    /**
     * Finds the first registered tool that can verify the given unit.
     *
     * @param unit the verification unit to route
     * @return the matching tool, or {@code null} if no tool supports this unit
     */
    private SignatureTool routeUnitToTool(VerificationUnit unit) {
        for (SignatureTool tool : tools) {
            if (tool.canVerify(unit)) {
                return tool;
            }
        }
        return null;
    }

    /**
     * Attempts to fetch a missing key from configured keyservers and re-verify.
     * <p>
     * If key fetching is disabled in {@link DiscoveryConfig}, or the key ID cannot be
     * extracted, or the import fails on all keyservers, the original result is returned unchanged.
     *
     * @param artifactFile the artifact being verified
     * @param unit the verification unit whose key is missing
     * @param tool the tool to retry verification with
     * @param originalResult the original {@link Verdict#NO_KEY} result
     * @return the result of re-verification after import, or the original result if fetching failed
     */
    private VerifyResult fetchKeyAndRetry(Path artifactFile, VerificationUnit unit,
            SignatureTool tool, VerifyResult originalResult) {
        if (!discoveryConfig.fetchSignerInfo()) {
            return originalResult;
        }

        String keyId = extractKeyIdFromUnit(unit);
        if (keyId == null) {
            return originalResult;
        }

        boolean imported = tryImportKey(keyId);
        if (!imported) {
            return originalResult;
        }

        return tool.verify(artifactFile, unit);
    }

    /**
     * Extracts the key ID (fingerprint) from a verification unit, if available.
     *
     * @param unit the verification unit
     * @return the issuer fingerprint for OpenPGP units, or {@code null} for unsupported unit types
     */
    private String extractKeyIdFromUnit(VerificationUnit unit) {
        if (unit instanceof OpenPgpVerificationUnit opgu) {
            return opgu.issuerFingerprint();
        }
        return null;
    }

    /**
     * Attempts to import a key by its ID from the configured keyservers.
     * <p>
     * Tries each keyserver in order and returns on the first successful import.
     *
     * @param keyId the key fingerprint to import
     * @return {@code true} if the key was successfully imported from any keyserver
     */
    private boolean tryImportKey(String keyId) {
        KeyImporter importer = findKeyImporter();
        if (importer == null) {
            return false;
        }

        for (String keyserver : discoveryConfig.keyservers()) {
            if (importer.importKey(keyId, keyserver)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds a {@link KeyImporter} among the registered tools.
     *
     * @return the first tool that implements {@link KeyImporter}, or {@code null} if none does
     */
    private KeyImporter findKeyImporter() {
        for (SignatureTool tool : tools) {
            if (tool instanceof KeyImporter ki) {
                return ki;
            }
        }
        return null;
    }

    /**
     * Wraps a verification result into an {@link EvidenceResult} by extracting
     * proven credentials from the tool.
     *
     * @param tool the tool that performed the verification
     * @param result the verification result to wrap
     * @return the evidence result containing the verification outcome and extracted credentials
     */
    private EvidenceResult wrapAsEvidence(SignatureTool tool, VerifyResult result) {
        List<Credential> credentials = tool.extractCredentials(result);
        return new EvidenceResult(result, credentials, name());
    }
}
