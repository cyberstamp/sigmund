package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.DiscoveryConfig;
import io.github.aloubyansky.sigmund.core.FileSignatureReport;
import io.github.aloubyansky.sigmund.core.KeyImporter;
import io.github.aloubyansky.sigmund.core.Sigmund;
import io.github.aloubyansky.sigmund.core.SignatureVerificationReport;
import io.github.aloubyansky.sigmund.core.UnverifiedResult;
import io.github.aloubyansky.sigmund.core.Verdict;
import io.github.aloubyansky.sigmund.core.VerifyResult;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;

/**
 * Inspects OpenPGP signatures for Maven artifacts, extracting signer metadata
 * from both classical (v4/GPG) and PQC (v6) signature blocks.
 * <p>
 * Uses the {@link Sigmund} facade for signature verification and
 * {@link ArtifactFileResolver} for Maven artifact resolution.
 */
class SignatureInspector {

    private final Log log;
    private final ArtifactFileResolver fileResolver;
    private final Sigmund sigmund;
    private final KeyImporter keyImporter;
    private final List<String> keyServers;
    private final Set<String> fetchedKeyIds = new HashSet<>();

    private SignatureInspector(Builder builder) {
        this.log = builder.log;
        this.fileResolver = new ArtifactFileResolver(
                builder.repoSystem, builder.repoSession, builder.remoteRepos, builder.log);
        this.sigmund = builder.sigmund;
        this.keyImporter = sigmund.findTool(KeyImporter.class);
        this.keyServers = List.copyOf(builder.keyServers);
    }

    static Builder builder() {
        return new Builder();
    }

    static class Builder {
        private Log log;
        private RepositorySystem repoSystem;
        private RepositorySystemSession repoSession;
        private List<RemoteRepository> remoteRepos;
        private Sigmund sigmund;
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

        Builder sigmund(Sigmund sigmund) {
            this.sigmund = sigmund;
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
            if (sigmund == null) {
                Map<String, Map<String, String>> overrides = SequoiaHomeResolver.toolOverrides(sqHome);
                sigmund = Sigmund.builder()
                        .discover()
                        .discoveryConfig(new DiscoveryConfig(true, false, List.of(), overrides))
                        .build();
            }
            return new SignatureInspector(this);
        }
    }

    static String versionLabel(int version) {
        return io.github.aloubyansky.sigmund.core.Algorithms.versionLabel(version);
    }

    List<SignedArtifact> inspectAll(Collection<ArtifactCoords> artifacts) {
        List<SignedArtifact> results = new ArrayList<>();
        for (ArtifactCoords artifact : artifacts) {
            results.addAll(inspectSignatures(artifact));
        }
        return results;
    }

    List<SignedArtifact> inspectSignatures(ArtifactCoords coords) {
        String coordsStr = coords.toString();

        ArtifactFileResolver.ResolvedArtifact resolved = fileResolver.resolveArtifact(coords);
        if (resolved == null) {
            return List.of(new SignedArtifact(coordsStr, null, Verdict.SKIPPED));
        }

        List<RemoteRepository> sigRepos = fileResolver.signatureRepos(resolved.sourceRepo());
        ArtifactFileResolver.ResolvedSignature sigResult = fileResolver.resolveSignature(
                coords, ".asc", sigRepos);
        if (sigResult == null) {
            return List.of(new SignedArtifact(coordsStr, null, Verdict.SKIPPED));
        }

        String repoId = sigResult.repoId();
        Path ascFile = sigResult.signatureFile();

        SignatureVerificationReport report;
        try {
            report = sigmund.verify(resolved.artifactFile(), ascFile);
        } catch (Exception e) {
            log.warn("Verification failed for " + coordsStr + ": " + e.getMessage());
            return List.of(new SignedArtifact(coordsStr, repoId, Verdict.FAIL));
        }

        if (report.files().isEmpty()) {
            return List.of(new SignedArtifact(coordsStr, repoId, Verdict.SKIPPED));
        }

        List<SignedArtifact> entries = new ArrayList<>();
        for (FileSignatureReport fileReport : report.files()) {
            if (fileReport.results().isEmpty()) {
                entries.add(new SignedArtifact(coordsStr, repoId, Verdict.SKIPPED));
                continue;
            }
            for (VerifyResult vr : fileReport.results()) {
                SignedArtifact entry = new SignedArtifact(coordsStr, repoId, vr,
                        resolved.artifactFile(), ascFile);
                SignedArtifact fetched;
                try {
                    fetched = fetchSignerInfoIfMissing(entry);
                } catch (Exception e) {
                    log.debug("Signer info fetch failed for " + coordsStr + ": " + e.getMessage());
                    fetched = entry;
                }
                entries.add(fetched);
            }
        }

        return entries;
    }

    SignedArtifact fetchSignerInfoIfMissing(SignedArtifact entry) {
        String id = entry.verifyResult().signerIdentifier();
        if (keyServers.isEmpty() || id == null
                || entry.verifyResult().signerDisplayName() != null) {
            return entry;
        }
        if (keyImporter == null) {
            return entry;
        }
        if (!fetchedKeyIds.add(id)) {
            return reverify(entry);
        }
        for (String server : keyServers) {
            if (keyImporter.importKey(id, server)) {
                return reverify(entry);
            }
        }
        return entry;
    }

    private SignedArtifact reverify(SignedArtifact entry) {
        if (entry.artifactFile() == null || entry.signatureFile() == null) {
            return entry;
        }
        try {
            SignatureVerificationReport report = sigmund.verify(
                    entry.artifactFile(), entry.signatureFile());
            if (report.files().isEmpty()) {
                return entry;
            }
            String entryId = entry.verifyResult().signerIdentifier();
            FileSignatureReport fileReport = report.files().get(0);
            for (VerifyResult vr : fileReport.results()) {
                String id = vr.signerIdentifier();
                if (id != null && id.equalsIgnoreCase(entryId)) {
                    return new SignedArtifact(entry.coordinates(), entry.repoId(),
                            vr, entry.artifactFile(), entry.signatureFile());
                }
            }
        } catch (Exception e) {
            log.debug("Re-verification failed: " + e.getMessage());
        }
        return entry;
    }

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

    record SignedArtifact(String coordinates, String repoId,
            VerifyResult verifyResult, Path artifactFile, Path signatureFile) {

        SignedArtifact(String coordinates, String repoId, Verdict verdict) {
            this(coordinates, repoId, new UnverifiedResult(verdict), null, null);
        }

        Verdict verdict() {
            return verifyResult.verdict();
        }
    }
}
