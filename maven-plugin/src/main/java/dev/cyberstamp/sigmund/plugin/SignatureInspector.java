package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Algorithms;
import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.FileSignatureReport;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import dev.cyberstamp.sigmund.core.KeyImporter;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SignatureVerificationReport;
import dev.cyberstamp.sigmund.core.UnverifiedResult;
import dev.cyberstamp.sigmund.core.VerifyResult;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
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
class SignatureInspector implements AutoCloseable {

    private final Log log;
    private final ArtifactFileResolver fileResolver;
    private final Sigmund sigmund;
    private final KeyImporter keyImporter;

    private SignatureInspector(Builder builder) {
        this.log = builder.log;
        this.fileResolver = new ArtifactFileResolver(
                builder.repoSystem, builder.repoSession, builder.remoteRepos, builder.log,
                builder.sigmund.signatureFileExtensions());
        this.sigmund = builder.sigmund;
        this.keyImporter = sigmund.findTool(KeyImporter.class);
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

        SignatureInspector build() throws MojoExecutionException {
            if (sigmund == null) {
                sigmund = Sigmund.builder()
                        .discoveryConfig(new DiscoveryConfig(true, false, List.of(), null))
                        .toolsConfig(SequoiaHomeResolver.toolsConfigOverrides(sqHome))
                        .build();
            }
            return new SignatureInspector(this);
        }
    }

    static String versionLabel(int version) {
        return Algorithms.versionLabel(version);
    }

    List<SignedArtifact> inspectAll(Collection<ArtifactCoords> artifacts) {
        List<SignedArtifact> results = new ArrayList<>();
        for (ArtifactCoords artifact : artifacts) {
            results.addAll(inspectSignatures(artifact));
        }
        return results;
    }

    List<SignedArtifact> inspectSignatures(ArtifactCoords coords) {
        ArtifactFileResolver.ResolvedArtifact resolved = fileResolver.resolveArtifact(coords);
        if (resolved == null) {
            return List.of(SignedArtifact.noClaim(coords, null));
        }

        List<RemoteRepository> sigRepos = fileResolver.signatureRepos(resolved.sourceRepo());
        List<ArtifactFileResolver.ResolvedSignature> sigResults = resolveAllSignatures(coords, sigRepos);
        if (sigResults.isEmpty()) {
            return List.of(SignedArtifact.noClaim(coords, null));
        }

        List<SignedArtifact> entries = new ArrayList<>();
        for (ArtifactFileResolver.ResolvedSignature sigResult : sigResults) {
            String repoId = sigResult.repoId();
            Path sigFile = sigResult.signatureFile();

            SignatureVerificationReport report;
            try {
                report = sigmund.verify(resolved.artifactFile(), sigFile);
            } catch (Exception e) {
                log.warn("Verification failed for " + coords + ": " + e.getMessage());
                entries.add(SignedArtifact.toolUnavailable(coords, repoId));
                continue;
            }

            if (report.files().isEmpty()) {
                entries.add(SignedArtifact.noClaim(coords, repoId));
                continue;
            }

            for (FileSignatureReport fileReport : report.files()) {
                if (fileReport.results().isEmpty()) {
                    entries.add(SignedArtifact.noClaim(coords, repoId));
                    continue;
                }
                for (VerifyResult vr : fileReport.results()) {
                    SignedArtifact entry = new SignedArtifact(coords, repoId, vr,
                            resolved.artifactFile(), sigFile);
                    SignedArtifact fetched;
                    try {
                        fetched = fetchSignerInfoIfMissing(entry);
                    } catch (Exception e) {
                        log.debug("Signer info fetch failed for " + coords + ": " + e.getMessage());
                        fetched = entry;
                    }
                    entries.add(fetched);
                }
            }
        }

        return entries;
    }

    private List<ArtifactFileResolver.ResolvedSignature> resolveAllSignatures(
            ArtifactCoords coords, List<RemoteRepository> sigRepos) {
        List<ArtifactFileResolver.ResolvedSignature> results = new ArrayList<>(sigRepos.size());
        for (String ext : sigmund.signatureFileExtensions()) {
            ArtifactFileResolver.ResolvedSignature sig = fileResolver.resolveSignature(coords, ext, sigRepos);
            if (sig != null) {
                results.add(sig);
            }
        }
        return results;
    }

    SignedArtifact fetchSignerInfoIfMissing(SignedArtifact entry) {
        String id = entry.verifyResult().signerIdentifier();
        if (id == null || entry.verifyResult().signerDisplayName() != null) {
            return entry;
        }
        if (keyImporter == null) {
            return entry;
        }
        if (keyImporter.fetchKey(id)) {
            return reverify(entry);
        }
        return entry;
    }

    private SignedArtifact reverify(SignedArtifact entry) {
        if (entry.artifactFile() == null || entry.signatureFile() == null) {
            return entry;
        }
        try {
            SignatureVerificationReport report = sigmund.verify(entry.artifactFile(), entry.signatureFile());
            if (report.files().isEmpty()) {
                return entry;
            }
            String entryId = entry.verifyResult().signerIdentifier();
            FileSignatureReport fileReport = report.files().get(0);
            for (VerifyResult vr : fileReport.results()) {
                String id = vr.signerIdentifier();
                if (id != null && id.equalsIgnoreCase(entryId)) {
                    return new SignedArtifact(entry.coords(), entry.repoId(),
                            vr, entry.artifactFile(), entry.signatureFile());
                }
            }
        } catch (Exception e) {
            log.debug("Re-verification failed: " + e.getMessage());
        }
        return entry;
    }

    @Override
    public void close() {
        sigmund.close();
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

    record SignedArtifact(ArtifactCoords coords, String repoId,
            VerifyResult verifyResult, Path artifactFile, Path signatureFile) {

        /**
         * Records an artifact for which no claim was found at all — no signature file
         * resolved, or one that yielded nothing to verify. This is the absence of
         * evidence, not a failed or indeterminate claim.
         */
        static SignedArtifact noClaim(ArtifactCoords coords, String repoId) {
            return new SignedArtifact(coords, repoId, null, null, null);
        }

        /** Records an artifact whose verification tool could not be run. */
        static SignedArtifact toolUnavailable(ArtifactCoords coords, String repoId) {
            return new SignedArtifact(coords, repoId,
                    new UnverifiedResult(ClaimOutcome.INDETERMINATE,
                            IndeterminateReason.TOOL_UNAVAILABLE),
                    null, null);
        }

        boolean hasClaim() {
            return verifyResult != null;
        }

        boolean isVerified() {
            return verifyResult != null && verifyResult.isVerified();
        }

        boolean isFailed() {
            return verifyResult != null && verifyResult.isFailed();
        }

        boolean isIndeterminate(IndeterminateReason expected) {
            return verifyResult != null && verifyResult.isIndeterminate(expected);
        }

        /**
         * Whether this entry carries a claim the report can attribute to a signer. An
         * artifact with no signature at all has no claim, and a claim no installed tool
         * supports cannot name a key, so neither can be grouped under a signer.
         */
        boolean hasAttributableClaim() {
            return hasClaim() && !isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
    }
}
