package io.github.aloubyansky.pqc.maven.plugin;

import io.github.aloubyansky.pqc.maven.core.AscCombiner;
import io.github.aloubyansky.pqc.maven.core.GpgRunner;
import io.github.aloubyansky.pqc.maven.core.SignatureBlockVerifier;
import io.github.aloubyansky.pqc.maven.core.SignatureInfo;
import io.github.aloubyansky.pqc.maven.core.SqRunner;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

/**
 * Inspects OpenPGP signatures for Maven artifacts, extracting signer metadata
 * from both classical (v4/GPG) and PQC (v6) signature blocks.
 * <p>
 * Shared between {@link DependencySignersMojo} and {@link VerifyMojo}.
 */
class SignatureInspector {

    private final Log log;
    private final RepositorySystem repoSystem;
    private final RepositorySystemSession repoSession;
    private final List<RemoteRepository> remoteRepos;
    private final GpgRunner gpg; // retained for fetchSignerInfoIfMissing/reverify
    private final SignatureBlockVerifier blockVerifier;
    private final List<String> keyServers;
    private final Set<String> fetchedKeyIds = new HashSet<>();

    private SignatureInspector(Builder builder) {
        this.log = builder.log;
        this.repoSystem = builder.repoSystem;
        this.repoSession = builder.repoSession;
        this.remoteRepos = builder.remoteRepos;
        this.gpg = builder.gpg;
        this.blockVerifier = new SignatureBlockVerifier(builder.gpg, builder.sq);
        this.keyServers = List.copyOf(builder.keyServers);
    }

    /**
     * Creates a new builder for configuring a {@link SignatureInspector}.
     */
    static Builder builder() {
        return new Builder();
    }

    static class Builder {
        private Log log;
        private RepositorySystem repoSystem;
        private RepositorySystemSession repoSession;
        private List<RemoteRepository> remoteRepos;
        private GpgRunner gpg;
        private SqRunner sq;
        private File sqHome;
        private final List<String> keyServers = new ArrayList<>();

        Builder log(Log log) {
            this.log = log;
            return this;
        }

        Builder repoSystem(RepositorySystem repoSystem) {
            this.repoSystem = repoSystem;
            return this;
        }

        Builder repoSession(RepositorySystemSession repoSession) {
            this.repoSession = repoSession;
            return this;
        }

        Builder remoteRepos(List<RemoteRepository> remoteRepos) {
            this.remoteRepos = remoteRepos;
            return this;
        }

        Builder gpgRunner(GpgRunner gpg) {
            this.gpg = gpg;
            return this;
        }

        Builder sqRunner(SqRunner sq) {
            this.sq = sq;
            return this;
        }

        Builder sqHome(File sqHome) {
            this.sqHome = sqHome;
            return this;
        }

        Builder addKeyServer(String server) {
            this.keyServers.add(server);
            return this;
        }

        SignatureInspector build() throws MojoExecutionException {
            if (gpg == null) {
                if (!GpgRunner.isAvailable()) {
                    throw new MojoExecutionException("GPG is not available on the system PATH");
                }
                gpg = new GpgRunner();
            }
            if (sq == null) {
                sq = createSqRunner(sqHome, log);
            }
            return new SignatureInspector(this);
        }
    }

    private static SqRunner createSqRunner(File sqHome, Log log) throws MojoExecutionException {
        if (!SqRunner.isAvailable()) {
            if (log != null) {
                log.debug("Sequoia (sq) not found - PQC signer info will not be available");
            }
            return null;
        }
        return new SqRunner(SequoiaHomeResolver.resolve(sqHome));
    }

    /**
     * Returns a human-readable label for the given OpenPGP signature version (e.g. "GPG", "PQC").
     */
    static String versionLabel(int version) {
        return switch (version) {
            case 4 -> "GPG";
            case 6 -> "PQC";
            default -> version > 0 ? "OpenPGP v" + version : "-";
        };
    }

    /**
     * Inspects signatures for all given artifacts, returning a flat list of results.
     * Each artifact may produce multiple entries (one per signature block).
     */
    List<SignedArtifact> inspectAll(Collection<ArtifactCoords> artifacts) {
        List<SignedArtifact> results = new ArrayList<>();
        for (ArtifactCoords artifact : artifacts) {
            results.addAll(inspectSignatures(artifact));
        }
        return results;
    }

    /**
     * Resolves the artifact, downloads its {@code .asc} signature and inspects each armored block.
     * Returns one {@link SignedArtifact} per block, or a single {@code NOT_PRESENT} entry if no
     * signature file exists.
     */
    List<SignedArtifact> inspectSignatures(ArtifactCoords coords) {
        String coordsStr = coords.toString();

        ResolvedArtifact resolved = resolveArtifact(coords);
        if (resolved == null) {
            return List.of(new SignedArtifact(coordsStr, null,
                    new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT)));
        }

        List<RemoteRepository> sigRepos = resolved.sourceRepo != null
                ? List.of(resolved.sourceRepo)
                : remoteRepos;
        ArtifactResult sigResult = resolveSignature(coords, sigRepos);
        if (sigResult == null) {
            return List.of(new SignedArtifact(coordsStr, null,
                    new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT)));
        }

        String repoId = resolveRepoId(sigResult);
        String ascContent;
        try {
            ascContent = Files.readString(sigResult.getArtifact().getFile().toPath());
        } catch (IOException e) {
            log.warn("Failed to read .asc file for " + coordsStr);
            return List.of(new SignedArtifact(coordsStr, repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.FAIL)));
        }

        List<String> blocks = AscCombiner.extractAllBlocks(ascContent);
        if (blocks.isEmpty()) {
            return List.of(new SignedArtifact(coordsStr, repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT)));
        }

        List<SignedArtifact> entries = new ArrayList<>();
        for (String block : blocks) {
            AscCombiner.SignaturePacketInfo pktInfo = AscCombiner.inspectSignaturePacket(block);
            int version = pktInfo.version();

            if (version > 0 && version <= 4) {
                entries.add(inspectGpgBlock(coordsStr, repoId, block,
                        pktInfo, resolved.artifactFile));
            } else {
                entries.add(inspectBlock(coordsStr, repoId, block,
                        pktInfo, resolved.artifactFile));
            }
        }

        return entries;
    }

    /**
     * Attempts to resolve signer identity by fetching the GPG key from configured keyservers
     * when the entry has a key ID but no signer user ID. Re-verifies the signature after
     * a successful key fetch to populate the signer metadata.
     *
     * @return the original entry if no fetch was needed, or a re-verified entry with updated metadata
     */
    SignedArtifact fetchSignerInfoIfMissing(SignedArtifact entry) {
        SignatureInfo sig = entry.signatureInfo();
        if (keyServers.isEmpty() || sig.keyId() == null || sig.signerUserId() != null) {
            return entry;
        }
        if (!fetchedKeyIds.add(sig.keyId())) {
            // already attempted this key — re-verify to pick up the fetched key
            return reverify(entry);
        }
        for (String server : keyServers) {
            if (gpg.receiveKey(sig.keyId(), server)) {
                return reverify(entry);
            }
        }
        return entry;
    }

    /** Re-runs GPG verification to pick up newly fetched key metadata. */
    private SignedArtifact reverify(SignedArtifact entry) {
        if (entry.artifactFile() == null || entry.signatureFile() == null) {
            return entry;
        }
        GpgRunner.VerifyResult verified = gpg.verify(entry.artifactFile(), entry.signatureFile());
        return new SignedArtifact(entry.coordinates(), entry.repoId(),
                new SignatureInfo(entry.signatureInfo().version(), verified.keyId(),
                        verified.algorithm(), verified.signerUserId(), verified.result()),
                entry.artifactFile(), entry.signatureFile());
    }

    private SignedArtifact inspectBlock(String coords, String repoId, String block,
            AscCombiner.SignaturePacketInfo pktInfo, Path artifactFile) {
        try {
            SignatureInfo sig = blockVerifier.verify(artifactFile, block, pktInfo);
            return new SignedArtifact(coords, repoId, sig);
        } catch (Exception e) {
            log.debug("Verification failed for " + coords + ": " + e.getMessage());
            return new SignedArtifact(coords, repoId,
                    new SignatureInfo(pktInfo.version(), pktInfo.issuerFingerprint(),
                            null, null, VerificationResult.FAIL));
        }
    }

    private SignedArtifact inspectGpgBlock(String coords, String repoId, String block,
            AscCombiner.SignaturePacketInfo pktInfo, Path artifactFile) {
        int effectiveVersion = pktInfo.version() > 0 ? pktInfo.version() : 4;
        Path gpgSigFile = null;
        try {
            gpgSigFile = Files.createTempFile("gpg-sig-", ".asc");
            Files.writeString(gpgSigFile, block);
            SignatureInfo sig = blockVerifier.verifyGpgBlock(artifactFile, gpgSigFile, effectiveVersion);
            SignedArtifact entry = new SignedArtifact(coords, repoId, sig,
                    artifactFile, gpgSigFile);
            SignedArtifact fetched;
            try {
                fetched = fetchSignerInfoIfMissing(entry);
            } catch (Exception e) {
                log.debug("Signer info fetch failed for " + coords + ": " + e.getMessage());
                fetched = entry;
            }
            return new SignedArtifact(fetched.coordinates(), fetched.repoId(),
                    fetched.signatureInfo());
        } catch (Exception e) {
            log.debug("GPG verification failed for " + coords + ": " + e.getMessage());
            return new SignedArtifact(coords, repoId,
                    new SignatureInfo(effectiveVersion, null, null, null, VerificationResult.FAIL));
        } finally {
            deleteTempFile(gpgSigFile);
        }
    }

    /**
     * Resolves the artifact to obtain its local file and the remote repository
     * it was originally fetched from.
     */
    private ResolvedArtifact resolveArtifact(ArtifactCoords coords) {
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                    coords.groupId(), coords.artifactId(),
                    coords.classifier(), coords.type(), coords.version());
            ArtifactRequest request = new ArtifactRequest(aetherArtifact, remoteRepos, null);
            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
            Path file = result.getArtifact().getFile().toPath();
            RemoteRepository sourceRepo = extractSourceRepo(result);
            return new ResolvedArtifact(file, sourceRepo);
        } catch (ArtifactResolutionException e) {
            log.debug("Could not resolve " + coords);
            return null;
        }
    }

    /** Extracts the source remote repository from a resolution result. */
    private RemoteRepository extractSourceRepo(ArtifactResult result) {
        if (result.getLocalArtifactResult() != null
                && result.getLocalArtifactResult().getRepository() != null) {
            return findMatchingRepo(result.getLocalArtifactResult().getRepository().getId());
        }
        ArtifactRepository repo = result.getRepository();
        if (repo instanceof RemoteRepository) {
            return (RemoteRepository) repo;
        }
        if (repo != null) {
            return findMatchingRepo(repo.getId());
        }
        return null;
    }

    /** Resolves the {@code .asc} signature artifact from the given repositories. */
    private ArtifactResult resolveSignature(ArtifactCoords coords, List<RemoteRepository> repos) {
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                    coords.groupId(), coords.artifactId(),
                    coords.classifier(), coords.type() + ".asc",
                    coords.version());
            ArtifactRequest request = new ArtifactRequest(aetherArtifact, repos, null);
            return repoSystem.resolveArtifact(repoSession, request);
        } catch (ArtifactResolutionException e) {
            log.debug("No .asc signature found for " + coords);
            return null;
        }
    }

    /** Finds the configured remote repository matching the given ID. */
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

    /** Extracts the repository ID from a resolved artifact result. */
    private String resolveRepoId(ArtifactResult result) {
        if (result.getLocalArtifactResult() != null
                && result.getLocalArtifactResult().getRepository() != null) {
            return result.getLocalArtifactResult().getRepository().getId();
        }
        ArtifactRepository repo = result.getRepository();
        return repo != null ? repo.getId() : null;
    }

    private static void deleteTempFile(Path file) {
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
            }
        }
    }

    /** Splits a comma-separated keyserver string into a trimmed, non-empty list. */
    static List<String> parseKeyservers(String keyservers) {
        List<String> servers = new ArrayList<>();
        for (String s : keyservers.split(",")) {
            String trimmed = s.trim();
            if (!trimmed.isEmpty()) {
                servers.add(trimmed);
            }
        }
        return servers;
    }

    record ResolvedArtifact(Path artifactFile, RemoteRepository sourceRepo) {
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
