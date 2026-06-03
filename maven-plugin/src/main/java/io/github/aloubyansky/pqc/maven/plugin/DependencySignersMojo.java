package io.github.aloubyansky.pqc.maven.plugin;

import io.github.aloubyansky.pqc.maven.core.AscCombiner;
import io.github.aloubyansky.pqc.maven.core.GpgRunner;
import io.github.aloubyansky.pqc.maven.core.SignatureInfo;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
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
        Set<Artifact> artifacts = resolveDependencies();
        getLog().info("Inspecting signatures for " + artifacts.size() + " dependency(ies)...");
        getLog().info("");

        List<ArtifactSigner> results = new ArrayList<>();
        for (Artifact artifact : artifacts) {
            results.addAll(inspectSignatures(artifact, gpg));
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

    List<ArtifactSigner> inspectSignatures(Artifact artifact, GpgRunner gpg) {
        String coords = formatCoordinates(artifact);

        ResolvedSignature resolved = downloadSignatureWithRepo(artifact);
        if (resolved == null) {
            return List.of(new ArtifactSigner(coords, null,
                    new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT)));
        }

        String ascContent;
        try {
            ascContent = Files.readString(resolved.path);
        } catch (IOException e) {
            getLog().warn("Failed to read .asc file for " + coords);
            return List.of(new ArtifactSigner(coords, resolved.repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.FAIL)));
        }

        List<String> blocks = AscCombiner.extractAllBlocks(ascContent);
        if (blocks.isEmpty()) {
            return List.of(new ArtifactSigner(coords, resolved.repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT)));
        }

        List<ArtifactSigner> entries = new ArrayList<>();
        Path artifactFile = artifact.getFile().toPath();

        for (String block : blocks) {
            int version = AscCombiner.detectSignatureVersion(block);

            if (version >= 6) {
                entries.add(new ArtifactSigner(coords, resolved.repoId,
                        new SignatureInfo(version, null, null, null, VerificationResult.SKIPPED)));
            } else {
                if (entries.stream().noneMatch(e -> e.signatureInfo.version() > 0
                        && e.signatureInfo.version() <= 4)) {
                    GpgRunner.VerifyResult result = gpg.verify(artifactFile, resolved.path);
                    entries.add(new ArtifactSigner(coords, resolved.repoId,
                            new SignatureInfo(version > 0 ? version : 4, result.keyId(),
                                    result.algorithm(), result.signerUserId(), result.result()),
                            artifactFile, resolved.path));
                }
            }
        }

        return entries;
    }

    void fetchMissingSignerInfo(List<ArtifactSigner> results, GpgRunner gpg) {
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
            ArtifactSigner entry = results.get(i);
            SignatureInfo sig = entry.signatureInfo;
            if (sig.keyId() != null && fetchedKeyIds.contains(sig.keyId())
                    && entry.artifactFile() != null && entry.signatureFile() != null) {
                GpgRunner.VerifyResult verified = gpg.verify(entry.artifactFile(), entry.signatureFile());
                results.set(i, new ArtifactSigner(entry.coordinates, entry.repoId,
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

    private void logReport(List<ArtifactSigner> results) {
        getLog().info("Dependency Signers:");

        int maxCoords = 0;
        int maxRepoId = 0;
        int maxKeyId = 0;
        for (ArtifactSigner r : results) {
            maxCoords = Math.max(maxCoords, r.coordinates.length());
            if (r.repoId != null) {
                maxRepoId = Math.max(maxRepoId, r.repoId.length());
            }
            if (r.signatureInfo.keyId() != null) {
                maxKeyId = Math.max(maxKeyId, r.signatureInfo.keyId().length());
            }
        }

        String format = "  %-" + maxCoords + "s   %-" + Math.max(maxRepoId, 4) + "s   %-3s   %-"
                + Math.max(maxKeyId, 6) + "s   %s";

        for (ArtifactSigner r : results) {
            SignatureInfo sig = r.signatureInfo;
            String repoId = r.repoId != null ? r.repoId : "-";
            String ver = versionLabel(sig.version());
            String keyId = sig.keyId() != null ? sig.keyId() : "-";
            String signer;
            if (sig.result() == VerificationResult.NOT_PRESENT) {
                signer = "(no signature)";
            } else if (sig.result() == VerificationResult.FAIL) {
                signer = "(BAD SIGNATURE)";
            } else if (sig.result() == VerificationResult.NO_KEY) {
                signer = "(key not in keyring)";
            } else if (sig.result() == VerificationResult.SKIPPED) {
                signer = "(detected, not verified)";
            } else if (sig.signerUserId() != null) {
                signer = sig.signerUserId();
            } else {
                signer = "(verified, signer unknown)";
            }

            if (sig.result() == VerificationResult.FAIL) {
                getLog().error(String.format(format, r.coordinates, repoId, ver, keyId, signer));
            } else if (sig.result() == VerificationResult.NOT_PRESENT
                    || sig.result() == VerificationResult.NO_KEY
                    || sig.result() == VerificationResult.SKIPPED) {
                getLog().warn(String.format(format, r.coordinates, repoId, ver, keyId, signer));
            } else {
                getLog().info(String.format(format, r.coordinates, repoId, ver, keyId, signer));
            }
        }

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
        getLog().info(summary.toString());
    }

    static String versionLabel(int version) {
        return switch (version) {
            case 4 -> "GPG";
            case 6 -> "PQC";
            default -> version > 0 ? "OpenPGP v" + version : "-";
        };
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

    record ArtifactSigner(String coordinates, String repoId, SignatureInfo signatureInfo,
            Path artifactFile, Path signatureFile) {
        ArtifactSigner(String coordinates, String repoId, SignatureInfo signatureInfo) {
            this(coordinates, repoId, signatureInfo, null, null);
        }
    }
}
