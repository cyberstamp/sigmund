package io.github.aloubyansky.pqc.maven.plugin;

import io.github.aloubyansky.pqc.maven.core.AscCombiner;
import io.github.aloubyansky.pqc.maven.core.GpgRunner;
import io.github.aloubyansky.pqc.maven.core.SignatureInfo;
import io.github.aloubyansky.pqc.maven.core.SqRunner;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

/**
 * Reports signer information for all project dependencies by downloading and
 * inspecting their signature files (.asc).
 * <p>
 * Each armored block in a signature file is reported separately, with its OpenPGP
 * version (v4 for classical, v6 for PQC). Classical (v4) signatures are verified
 * via GPG to extract the signer's key ID and user ID. PQC (v6) signatures are
 * detected but not yet verified.
 * <p>
 * The signature file is downloaded from the same remote repository that provided the
 * artifact itself, ensuring the reported signer matches the actual artifact in use.
 */
@Mojo(name = "dependency-signers", defaultPhase = LifecyclePhase.VALIDATE, requiresDependencyResolution = ResolutionScope.TEST, threadSafe = true)
public class DependencySignersMojo extends AbstractDependencyMojo {

    @Parameter(property = "pqc.fetchSignerInfo", defaultValue = "false")
    private boolean fetchSignerInfo;

    @Parameter(property = "pqc.keyservers", defaultValue = "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org")
    private String keyservers;

    @Parameter(property = "pqc.sqHome")
    private File sqHome;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping dependency signers report");
            return;
        }

        if (!GpgRunner.isAvailable()) {
            throw new MojoExecutionException("GPG is not available on the system PATH");
        }

        GpgRunner gpg = new GpgRunner();
        SqRunner sq = createSqRunner();
        Set<Artifact> artifacts = resolveDependencies();
        getLog().info("Inspecting signatures for " + artifacts.size() + " dependency(ies)...");
        getLog().info("");

        List<SignedArtifact> results = new ArrayList<>();
        for (Artifact artifact : artifacts) {
            results.addAll(inspectSignatures(artifact, gpg, sq));
        }

        if (fetchSignerInfo) {
            fetchMissingSignerInfo(results, gpg);
        }

        logReport(results);
    }

    static String formatCoordinates(Artifact artifact) {
        StringBuilder sb = new StringBuilder();
        sb.append(artifact.getGroupId()).append(':').append(artifact.getArtifactId());
        String type = artifact.getType();
        String classifier = artifact.getClassifier();
        boolean hasClassifier = classifier != null && !classifier.isEmpty();
        if (hasClassifier || (type != null && !"jar".equals(type))) {
            sb.append(':').append(type != null ? type : "jar");
        }
        if (hasClassifier) {
            sb.append(':').append(classifier);
        }
        sb.append(':').append(artifact.getVersion());
        return sb.toString();
    }

    List<SignedArtifact> inspectSignatures(Artifact artifact, GpgRunner gpg, SqRunner sq) {
        String coords = formatCoordinates(artifact);

        ResolvedSignature resolved = downloadSignatureWithRepo(artifact);
        if (resolved == null) {
            return List.of(new SignedArtifact(coords, null,
                    new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT)));
        }

        String ascContent;
        try {
            ascContent = Files.readString(resolved.path);
        } catch (IOException e) {
            getLog().warn("Failed to read .asc file for " + coords);
            return List.of(new SignedArtifact(coords, resolved.repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.FAIL)));
        }

        List<String> blocks = AscCombiner.extractAllBlocks(ascContent);
        if (blocks.isEmpty()) {
            return List.of(new SignedArtifact(coords, resolved.repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT)));
        }

        List<SignedArtifact> entries = new ArrayList<>();
        Path artifactFile = artifact.getFile().toPath();

        for (String block : blocks) {
            int version = AscCombiner.detectSignatureVersion(block);

            if (version >= 6) {
                String fingerprint = AscCombiner.extractV6IssuerFingerprint(block);
                entries.add(inspectPqcBlock(coords, resolved.repoId, block, fingerprint,
                        version, artifactFile, sq));
            } else {
                if (entries.stream().noneMatch(e -> e.signatureInfo.version() > 0
                        && e.signatureInfo.version() <= 4)) {
                    GpgRunner.VerifyResult result = gpg.verify(artifactFile, resolved.path);
                    entries.add(new SignedArtifact(coords, resolved.repoId,
                            new SignatureInfo(version > 0 ? version : 4, result.keyId(),
                                    result.algorithm(), result.signerUserId(), result.result()),
                            artifactFile, resolved.path));
                }
            }
        }

        return entries;
    }

    private SignedArtifact inspectPqcBlock(String coords, String repoId, String block,
            String fingerprint, int version, Path artifactFile, SqRunner sq) {
        if (sq == null || fingerprint == null) {
            return new SignedArtifact(coords, repoId,
                    new SignatureInfo(version, fingerprint, null, null, VerificationResult.SKIPPED));
        }

        SqRunner.CertInfo certInfo = sq.inspectCert(fingerprint);
        if (certInfo == null) {
            return new SignedArtifact(coords, repoId,
                    new SignatureInfo(version, fingerprint, null, null, VerificationResult.NO_KEY));
        }

        // Use the cert file from the cert-d store directly (avoids exportCert
        // resolution issues with PQC certs that sq considers "unusable")
        Path certFile = certInfo.certFile();
        if (certFile == null) {
            certFile = sq.findCertFile(fingerprint);
        }
        if (certFile == null) {
            return new SignedArtifact(coords, repoId,
                    new SignatureInfo(version, fingerprint, certInfo.algorithm(),
                            certInfo.userId(), VerificationResult.NO_KEY));
        }

        Path pqcSigFile = null;
        try {
            pqcSigFile = Files.createTempFile("pqc-sig-", ".asc");
            Files.writeString(pqcSigFile, block);

            boolean verified = sq.verifyCertFile(artifactFile, pqcSigFile, certFile);
            return new SignedArtifact(coords, repoId,
                    new SignatureInfo(version, fingerprint, certInfo.algorithm(),
                            certInfo.userId(), verified ? VerificationResult.PASS : VerificationResult.FAIL));
        } catch (Exception e) {
            return new SignedArtifact(coords, repoId,
                    new SignatureInfo(version, fingerprint, certInfo.algorithm(),
                            certInfo.userId(), VerificationResult.SKIPPED));
        } finally {
            deleteTempFile(pqcSigFile);
        }
    }

    private static void deleteTempFile(Path file) {
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
            }
        }
    }

    void fetchMissingSignerInfo(List<SignedArtifact> results, GpgRunner gpg) {
        Set<String> unknownKeyIds = results.stream()
                .map(r -> r.signatureInfo)
                .filter(s -> s.keyId() != null && s.signerUserId() == null)
                .map(SignatureInfo::keyId)
                .collect(Collectors.toCollection(java.util.LinkedHashSet::new));

        if (unknownKeyIds.isEmpty()) {
            return;
        }

        List<String> servers = parseKeyservers();
        getLog().info("Fetching " + unknownKeyIds.size() + " unknown key(s) from " + servers + "...");

        Set<String> fetchedKeyIds = new java.util.HashSet<>();
        for (String keyId : unknownKeyIds) {
            for (String server : servers) {
                if (gpg.receiveKey(keyId, server)) {
                    fetchedKeyIds.add(keyId);
                    break;
                }
            }
        }

        if (fetchedKeyIds.isEmpty()) {
            return;
        }

        for (int i = 0; i < results.size(); i++) {
            SignedArtifact entry = results.get(i);
            SignatureInfo sig = entry.signatureInfo;
            if (sig.keyId() != null && fetchedKeyIds.contains(sig.keyId())
                    && entry.artifactFile() != null && entry.signatureFile() != null) {
                GpgRunner.VerifyResult verified = gpg.verify(entry.artifactFile(), entry.signatureFile());
                results.set(i, new SignedArtifact(entry.coordinates, entry.repoId,
                        new SignatureInfo(sig.version(), verified.keyId(), verified.algorithm(),
                                verified.signerUserId(), verified.result()),
                        entry.artifactFile(), entry.signatureFile()));
            }
        }
    }

    private List<String> parseKeyservers() {
        List<String> servers = new ArrayList<>();
        for (String s : keyservers.split(",")) {
            String trimmed = s.trim();
            if (!trimmed.isEmpty()) {
                servers.add(trimmed);
            }
        }
        return servers;
    }

    private void logReport(List<SignedArtifact> results) {

        // Group entries by artifact coordinate
        Map<String, List<SignedArtifact>> byArtifact = new HashMap<>();
        for (SignedArtifact r : results) {
            byArtifact.computeIfAbsent(r.coordinates, k -> new ArrayList<>(2)).add(r);
        }

        // Build signature profile for each artifact and group by shared key sets
        Map<String, List<String>> profileToCoords = new HashMap<>();
        List<String> unsignedCoords = new ArrayList<>();

        for (var entry : byArtifact.entrySet()) {
            String coords = entry.getKey();
            List<SignedArtifact> signers = entry.getValue();

            boolean allUnsigned = signers.stream()
                    .allMatch(s -> s.signatureInfo.result() == VerificationResult.NOT_PRESENT);
            if (allUnsigned) {
                unsignedCoords.add(coords);
                continue;
            }

            String profileKey = signers.stream()
                    .filter(s -> s.signatureInfo.result() != VerificationResult.NOT_PRESENT)
                    .map(s -> s.signatureInfo.version() + ":"
                            + (s.signatureInfo.keyId() != null ? s.signatureInfo.keyId() : "?"))
                    .sorted()
                    .distinct()
                    .collect(Collectors.joining("|"));

            profileToCoords.computeIfAbsent(profileKey, k -> new ArrayList<>()).add(coords);
        }

        // Sort artifacts within each group alphabetically
        profileToCoords.values().forEach(list -> list.sort(Comparator.naturalOrder()));
        unsignedCoords.sort(Comparator.naturalOrder());

        // Sort groups alphabetically by signer name; unverified groups go last
        List<Map.Entry<String, List<String>>> sortedGroups = profileToCoords.entrySet().stream()
                .sorted((a, b) -> {
                    String signerA = firstSigner(a.getValue(), byArtifact);
                    String signerB = firstSigner(b.getValue(), byArtifact);
                    if (signerA != null && signerB != null) {
                        return signerA.compareToIgnoreCase(signerB);
                    }
                    if (signerA != null) {
                        return -1;
                    }
                    if (signerB != null) {
                        return 1;
                    }
                    return a.getKey().compareTo(b.getKey());
                })
                .toList();

        // Output signed groups
        boolean firstGroup = true;
        for (var groupEntry : sortedGroups) {
            if (!firstGroup) {
                getLog().info("");
            }
            firstGroup = false;

            List<String> coordsList = groupEntry.getValue();

            // Aggregate best key info across all artifacts in this group
            Map<String, SignatureInfo> keyInfos = new HashMap<>();
            for (String coords : coordsList) {
                for (SignedArtifact as : byArtifact.get(coords)) {
                    SignatureInfo sig = as.signatureInfo;
                    if (sig.result() == VerificationResult.NOT_PRESENT) {
                        continue;
                    }
                    String k = sig.version() + ":"
                            + (sig.keyId() != null ? sig.keyId() : "?");
                    keyInfos.merge(k, sig, (existing, incoming) -> new SignatureInfo(
                            existing.version(),
                            existing.keyId() != null ? existing.keyId() : incoming.keyId(),
                            existing.algorithm() != null ? existing.algorithm() : incoming.algorithm(),
                            existing.signerUserId() != null
                                    ? existing.signerUserId()
                                    : incoming.signerUserId(),
                            existing.result() == VerificationResult.PASS
                                    ? existing.result()
                                    : incoming.result()));
                }
            }

            // Sort key headers by version then keyId
            List<SignatureInfo> sortedKeys = keyInfos.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(Map.Entry::getValue)
                    .toList();

            boolean groupHasIssue = sortedKeys.stream()
                    .noneMatch(sig -> sig.signerUserId() != null);

            // Print per-key signer + key lines
            for (SignatureInfo sig : sortedKeys) {
                String ver = versionLabel(sig.version());
                String keyId = sig.keyId() != null ? sig.keyId() : "-";
                boolean verified = sig.signerUserId() != null;
                if (verified) {
                    getLog().info("Signer: " + sig.signerUserId());
                    getLog().info("   " + ver + ": " + keyId);
                } else {
                    getLog().warn("Signer: NOT VERIFIED");
                    getLog().warn("   " + ver + ": " + keyId);
                }
            }

            // Print artifacts
            for (String coords : coordsList) {
                boolean hasFail = byArtifact.get(coords).stream()
                        .anyMatch(as -> as.signatureInfo.result() == VerificationResult.FAIL);
                String line = "     " + coords;
                if (hasFail) {
                    getLog().error(line + "   (BAD SIGNATURE)");
                } else if (groupHasIssue) {
                    getLog().warn(line);
                } else {
                    getLog().info(line);
                }
            }
        }

        // Output unsigned group
        if (!unsignedCoords.isEmpty()) {
            if (!firstGroup) {
                getLog().info("");
            }
            getLog().warn("UNSIGNED");
            for (String coords : unsignedCoords) {
                getLog().warn("  " + coords);
            }
        }

        // Summary statistics
        long totalArtifacts = results.stream().map(r -> r.coordinates).distinct().count();
        Map<Integer, Long> versionCounts = results.stream()
                .filter(r -> r.signatureInfo.version() > 0)
                .collect(Collectors.groupingBy(r -> r.signatureInfo.version(), Collectors.counting()));
        long uniqueKeys = results.stream()
                .map(r -> r.signatureInfo.keyId())
                .filter(k -> k != null)
                .distinct()
                .count();
        long untrusted = results.stream()
                .filter(r -> r.signatureInfo.result() == VerificationResult.NOT_PRESENT
                        || r.signatureInfo.result() == VerificationResult.FAIL)
                .map(r -> r.coordinates)
                .distinct()
                .count();
        Set<String> identifiedCoords = results.stream()
                .filter(r -> r.signatureInfo.signerUserId() != null)
                .map(r -> r.coordinates)
                .collect(Collectors.toSet());
        long unidentified = results.stream()
                .filter(r -> r.signatureInfo.result() != VerificationResult.NOT_PRESENT
                        && r.signatureInfo.result() != VerificationResult.FAIL)
                .map(r -> r.coordinates)
                .distinct()
                .filter(c -> !identifiedCoords.contains(c))
                .count();

        getLog().info("");
        StringBuilder summary = new StringBuilder();
        if (untrusted == 0 && unidentified == 0) {
            summary.append("All clear: ");
        } else {
            if (untrusted > 0) {
                summary.append(untrusted).append(" untrusted");
            }
            if (unidentified > 0) {
                if (untrusted > 0) {
                    summary.append(", ");
                }
                summary.append(unidentified).append(" unidentified");
            }
            summary.append(": ");
        }
        summary.append(totalArtifacts).append(" dependencies");
        versionCounts.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> summary.append(", ").append(e.getValue()).append(" ")
                        .append(versionLabel(e.getKey())).append(" signature(s)"));
        summary.append(", ").append(uniqueKeys).append(" unique key(s)");
        getLog().info("Summary: " + summary);
    }

    static String versionLabel(int version) {
        return switch (version) {
            case 4 -> "GPG";
            case 6 -> "PQC";
            default -> version > 0 ? "OpenPGP v" + version : "-";
        };
    }

    private static String firstSigner(List<String> coordsList,
            Map<String, List<SignedArtifact>> byArtifact) {
        for (String coords : coordsList) {
            for (SignedArtifact as : byArtifact.get(coords)) {
                if (as.signatureInfo.signerUserId() != null) {
                    return as.signatureInfo.signerUserId();
                }
            }
        }
        return null;
    }

    private SqRunner createSqRunner() throws MojoExecutionException {
        if (!SqRunner.isAvailable()) {
            getLog().debug("Sequoia (sq) not found - PQC signer info will not be available");
            return null;
        }
        return new SqRunner(SequoiaHomeResolver.resolve(sqHome));
    }

    /**
     * Resolves the source remote repository for the given artifact, then downloads the .asc
     * signature from that same repository.
     */
    ResolvedSignature downloadSignatureWithRepo(Artifact artifact) {
        RemoteRepository sourceRepo = resolveSourceRepository(artifact);
        List<RemoteRepository> repos = sourceRepo != null ? List.of(sourceRepo) : remoteRepos;

        ArtifactResult result = resolveSignature(artifact, repos);
        if (result == null) {
            return null;
        }
        String repoId = resolveRepoId(result);
        return new ResolvedSignature(result.getArtifact().getFile().toPath(), repoId);
    }

    private RemoteRepository resolveSourceRepository(Artifact artifact) {
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                    artifact.getGroupId(),
                    artifact.getArtifactId(),
                    artifact.getClassifier(),
                    artifact.getType(),
                    artifact.getVersion());
            ArtifactRequest request = new ArtifactRequest(aetherArtifact, remoteRepos, null);
            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);

            if (result.getLocalArtifactResult() != null
                    && result.getLocalArtifactResult().getRepository() != null) {
                RemoteRepository origin = result.getLocalArtifactResult().getRepository();
                return findMatchingRepo(origin.getId());
            }

            ArtifactRepository repo = result.getRepository();
            if (repo instanceof RemoteRepository) {
                return (RemoteRepository) repo;
            }
            if (repo != null) {
                return findMatchingRepo(repo.getId());
            }
        } catch (ArtifactResolutionException e) {
            getLog().debug("Could not resolve source repository for " + artifact);
        }
        return null;
    }

    private RemoteRepository findMatchingRepo(String repoId) {
        if (repoId == null) {
            return null;
        }
        for (RemoteRepository repo : remoteRepos) {
            if (repoId.equals(repo.getId())) {
                return repo;
            }
        }
        return null;
    }

    private String resolveRepoId(ArtifactResult result) {
        if (result.getLocalArtifactResult() != null
                && result.getLocalArtifactResult().getRepository() != null) {
            return result.getLocalArtifactResult().getRepository().getId();
        }
        ArtifactRepository repo = result.getRepository();
        return repo != null ? repo.getId() : null;
    }

    record ResolvedSignature(Path path, String repoId) {
    }

    /**
     * Associates a resolved artifact with its signature metadata and optional file paths
     * for re-verification after key fetching.
     *
     * @param coordinates Maven coordinates (groupId:artifactId[:type][:classifier]:version)
     * @param repoId identifier of the remote repository the artifact was resolved from, or {@code null}
     * @param signatureInfo signature metadata (version, key ID, algorithm, signer, verification result)
     * @param artifactFile local path to the artifact file, retained for re-verification; may be {@code null}
     * @param signatureFile local path to the .asc signature file, retained for re-verification; may be {@code null}
     */
    record SignedArtifact(String coordinates, String repoId, SignatureInfo signatureInfo,
            Path artifactFile, Path signatureFile) {
        SignedArtifact(String coordinates, String repoId, SignatureInfo signatureInfo) {
            this(coordinates, repoId, signatureInfo, null, null);
        }
    }
}
