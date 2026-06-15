package io.github.aloubyansky.pqc.maven.plugin;

import io.github.aloubyansky.pqc.maven.core.AscCombiner;
import io.github.aloubyansky.pqc.maven.core.GpgRunner;
import io.github.aloubyansky.pqc.maven.core.HybridVerifier;
import io.github.aloubyansky.pqc.maven.core.PqcKeyConfig;
import io.github.aloubyansky.pqc.maven.core.SqRunner;
import io.github.aloubyansky.pqc.maven.core.VerificationReport;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

/**
 * Verifies GPG and PQC signatures of all project dependencies against a {@link KeysMap} configuration.
 * <p>
 * Each dependency's signature is downloaded from the remote repository and verified.
 * The goal supports configurable policies for unmapped artifacts and unchecked PQC signatures.
 *
 * @see KeysMap
 * @see HybridVerifier
 */
@Mojo(name = "verify-dependencies", defaultPhase = LifecyclePhase.VALIDATE, requiresDependencyResolution = ResolutionScope.TEST, threadSafe = true)
public class VerifyDependenciesMojo extends AbstractDependencyMojo {

    @Parameter(property = "pqc.keysMap", required = true)
    private File keysMap;

    @Parameter(property = "pqc.unmappedPolicy", defaultValue = "warn")
    private String unmappedPolicy;

    @Parameter(property = "pqc.failIfPqcUnchecked", defaultValue = "true")
    private boolean failIfPqcUnchecked;

    @Parameter(property = "pqc.sqHome")
    private File sqHome;

    @Parameter(property = "pqc.verifyPomFiles", defaultValue = "true")
    private boolean verifyPomFiles;

    private static final Set<String> VALID_UNMAPPED_POLICIES = Set.of("warn", "fail", "skip");

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping dependency signature verification");
            return;
        }

        if (!VALID_UNMAPPED_POLICIES.contains(unmappedPolicy)) {
            throw new MojoExecutionException(
                    "Invalid unmappedPolicy '" + unmappedPolicy + "'. Must be one of: warn, fail, skip");
        }

        KeysMap map = parseKeysMap();
        Set<Artifact> artifacts = resolveDependencies();
        getLog().info("Verifying " + artifacts.size() + " dependency signature(s)...");

        HybridVerifier verifier = createVerifier();

        List<ArtifactVerification> results = new ArrayList<>();
        for (Artifact artifact : artifacts) {
            ArtifactVerification result = verifyArtifact(artifact, map, verifier);
            results.add(result);
            logResult(result);

            if (verifyPomFiles) {
                ArtifactVerification pomResult = verifyPomArtifact(artifact, map, verifier);
                if (pomResult != null) {
                    results.add(pomResult);
                    logResult(pomResult);
                }
            }
        }

        logSummary(results);
        String failure = evaluatePolicy(results, unmappedPolicy, failIfPqcUnchecked);
        if (failure != null) {
            throw new MojoFailureException(failure);
        }
    }

    private KeysMap parseKeysMap() throws MojoExecutionException {
        if (!keysMap.exists()) {
            throw new MojoExecutionException("keysMap file not found: " + keysMap.getAbsolutePath());
        }
        try {
            return KeysMap.parse(keysMap.toPath(), project.getProperties()::getProperty);
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to parse keysMap file", e);
        }
    }

    ArtifactVerification verifyArtifact(Artifact artifact, KeysMap map,
            HybridVerifier verifier) {
        String groupId = artifact.getGroupId();
        String artifactId = artifact.getArtifactId();
        String version = artifact.getVersion();
        String type = artifact.getType();

        KeysMap.Entry entry = map.findMatch(groupId, artifactId);
        if (entry == null) {
            return new ArtifactVerification(groupId, artifactId, version, type,
                    null, null, null, false);
        }

        if (hasKeySpec(entry, KeysMap.KeySpec.Type.NO_SIG)) {
            return new ArtifactVerification(groupId, artifactId, version, type,
                    VerificationResult.SKIPPED, null, VerificationResult.SKIPPED, false);
        }

        Path ascFile = downloadSignature(artifact);
        if (ascFile == null) {
            return new ArtifactVerification(groupId, artifactId, version, type,
                    VerificationResult.NOT_PRESENT, null, VerificationResult.NOT_PRESENT, false);
        }

        Path artifactFile = artifact.getFile().toPath();
        PqcKeyConfig pqcConfig = buildPqcConfig(entry);
        boolean pqcUnchecked = false;

        VerificationReport report = verifier.verify(artifactFile, ascFile, pqcConfig);
        if (pqcConfig == null && hasPqcBlock(ascFile)) {
            pqcUnchecked = true;
        }

        VerificationResult gpgResult = report.classicResult();
        if (gpgResult == VerificationResult.PASS
                && !hasKeySpec(entry, KeysMap.KeySpec.Type.ANY)) {
            String expectedGpgFp = getGpgFingerprint(entry);
            if (expectedGpgFp != null && report.classicKeyId() != null
                    && !fingerprintsMatch(expectedGpgFp, report.classicKeyId())) {
                gpgResult = VerificationResult.FAIL;
            }
        }

        return new ArtifactVerification(groupId, artifactId, version, type,
                gpgResult, report.classicKeyId(),
                report.pqcResult(), pqcUnchecked);
    }

    private ArtifactVerification verifyPomArtifact(Artifact artifact, KeysMap map,
            HybridVerifier verifier) {
        try {
            org.eclipse.aether.artifact.Artifact pomAether = new DefaultArtifact(
                    artifact.getGroupId(),
                    artifact.getArtifactId(),
                    "",
                    "pom",
                    artifact.getVersion());
            ArtifactRequest request = new ArtifactRequest(pomAether, remoteRepos, null);
            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
            org.apache.maven.artifact.DefaultArtifact mavenArtifact = new org.apache.maven.artifact.DefaultArtifact(
                    artifact.getGroupId(), artifact.getArtifactId(),
                    artifact.getVersion(), artifact.getScope(),
                    "pom", "", null);
            mavenArtifact.setFile(result.getArtifact().getFile());
            return verifyArtifact(mavenArtifact, map, verifier);
        } catch (ArtifactResolutionException e) {
            getLog().debug("Could not resolve POM for " + artifact.getGroupId()
                    + ":" + artifact.getArtifactId() + ":" + artifact.getVersion() + ": " + e.getMessage());
            return null;
        }
    }

    private boolean hasPqcBlock(Path ascFile) {
        try {
            String content = Files.readString(ascFile);
            for (String block : AscCombiner.extractAllBlocks(content)) {
                if (AscCombiner.detectSignatureVersion(block) >= 6) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private PqcKeyConfig buildPqcConfig(KeysMap.Entry entry) {
        for (KeysMap.KeySpec spec : entry.keySpecs()) {
            if (spec.type() == KeysMap.KeySpec.Type.PQC_CERT) {
                return PqcKeyConfig.certFile(Path.of(spec.value()));
            }
            if (spec.type() == KeysMap.KeySpec.Type.PQC_FINGERPRINT) {
                return PqcKeyConfig.fingerprint(spec.value());
            }
        }
        return null;
    }

    private boolean hasKeySpec(KeysMap.Entry entry, KeysMap.KeySpec.Type type) {
        return entry.keySpecs().stream().anyMatch(s -> s.type() == type);
    }

    private String getGpgFingerprint(KeysMap.Entry entry) {
        return entry.keySpecs().stream()
                .filter(s -> s.type() == KeysMap.KeySpec.Type.GPG_FINGERPRINT)
                .map(KeysMap.KeySpec::value)
                .findFirst().orElse(null);
    }

    static final int MIN_FINGERPRINT_LENGTH = 16;

    static boolean fingerprintsMatch(String expected, String actual) {
        if (expected.length() < MIN_FINGERPRINT_LENGTH || actual.length() < MIN_FINGERPRINT_LENGTH) {
            return false;
        }
        String e = expected.toUpperCase();
        String a = actual.toUpperCase();
        if (e.length() >= a.length()) {
            return e.endsWith(a);
        }
        return a.endsWith(e);
    }

    private HybridVerifier createVerifier() throws MojoExecutionException {
        Path sequoiaHome = SequoiaHomeResolver.resolve(sqHome);
        GpgRunner gpg = new GpgRunner();
        SqRunner sq = null;
        if (SqRunner.isAvailable()) {
            sq = new SqRunner(sequoiaHome);
        } else {
            getLog().warn("Sequoia (sq) not found - PQC verification will be skipped");
        }
        return new HybridVerifier(gpg, sq);
    }

    private void logResult(ArtifactVerification v) {
        String coords = v.groupId + ":" + v.artifactId + ":" + v.version;
        if (v.gpgResult == null) {
            getLog().warn("  " + coords + "  (unmapped)");
        } else if (v.gpgResult == VerificationResult.NOT_PRESENT) {
            getLog().warn("  " + coords + "  GPG: NO_SIG  PQC: " + v.pqcResult);
        } else if (v.gpgResult == VerificationResult.FAIL || v.pqcResult == VerificationResult.FAIL) {
            getLog().error("  " + coords + "  GPG: " + v.gpgResult + "  PQC: " + v.pqcResult);
        } else if (v.pqcUnchecked) {
            getLog().warn("  " + coords + "  GPG: " + v.gpgResult
                    + "  PQC: PRESENT (unchecked - no key mapped)");
        } else {
            getLog().info("  " + coords + "  GPG: " + v.gpgResult + "  PQC: " + v.pqcResult);
        }
    }

    private void logSummary(List<ArtifactVerification> results) {
        long passed = results.stream().filter(v -> (v.gpgResult == VerificationResult.PASS
                || v.gpgResult == VerificationResult.SKIPPED)
                && v.pqcResult != VerificationResult.FAIL && !v.pqcUnchecked).count();
        long failed = results.stream().filter(v -> v.gpgResult == VerificationResult.FAIL
                || v.gpgResult == VerificationResult.NOT_PRESENT
                || v.pqcResult == VerificationResult.FAIL).count();
        long warnings = results.size() - passed - failed;
        getLog().info("");
        getLog().info("Summary: " + passed + " passed, " + warnings + " warning(s), "
                + failed + " failed");
    }

    static String evaluatePolicy(List<ArtifactVerification> results,
            String unmappedPolicy, boolean failIfPqcUnchecked) {
        List<String> failures = new ArrayList<>();
        for (ArtifactVerification v : results) {
            String coords = v.groupId + ":" + v.artifactId + ":" + v.version;
            if (v.gpgResult == null && "fail".equals(unmappedPolicy)) {
                failures.add(coords + ": unmapped artifact (no keysMap entry)");
            }
            if (v.gpgResult == VerificationResult.NOT_PRESENT) {
                failures.add(coords + ": no signature file found");
            } else if (v.gpgResult == VerificationResult.FAIL) {
                failures.add(coords + ": GPG signature verification failed");
            }
            if (v.pqcResult == VerificationResult.FAIL) {
                failures.add(coords + ": PQC signature verification failed");
            }
            if (v.pqcUnchecked && failIfPqcUnchecked) {
                failures.add(coords + ": PQC signature present but no key configured");
            }
        }
        if (failures.isEmpty()) {
            return null;
        }
        return failures.size() + " artifact(s) failed signature verification:\n"
                + String.join("\n", failures);
    }

    /** Holds the verification results for a single dependency artifact. */
    public record ArtifactVerification(
            String groupId,
            String artifactId,
            String version,
            String type,
            VerificationResult gpgResult,
            String gpgKeyId,
            VerificationResult pqcResult,
            boolean pqcUnchecked) {
    }
}
