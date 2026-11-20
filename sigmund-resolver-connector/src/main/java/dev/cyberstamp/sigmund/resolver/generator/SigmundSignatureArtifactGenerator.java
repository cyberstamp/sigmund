package dev.cyberstamp.sigmund.resolver.generator;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SignedFile;
import dev.cyberstamp.sigmund.core.Signer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.spi.artifact.generator.ArtifactGenerator;
import org.eclipse.aether.util.artifact.SubArtifact;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Signs the artifacts of one deploy request with Sigmund's signer, adding each signature file — {@code .asc}, or
 * another format a configured tool produces — as a sub-artifact to deploy beside the artifact it signs.
 *
 * <p>
 * Backs out when the request already holds signatures, as when the build attached them with maven-gpg-plugin. The
 * signatures are written to a temporary directory, deleted with the signing tools when the generator is closed.
 */
final class SigmundSignatureArtifactGenerator implements ArtifactGenerator {
    private static final Logger LOGGER = LoggerFactory.getLogger(SigmundSignatureArtifactGenerator.class);

    private final List<Artifact> artifacts;
    private final Predicate<Artifact> signable;
    private final Sigmund sigmund;
    private Path signatureDirectory;

    /**
     * Creates the generator, which owns {@code sigmund} and closes it.
     *
     * @param artifacts the artifacts of the deploy request
     * @param signable which artifacts get a signature: not checksums, nor signatures
     * @param sigmund the signing instance
     */
    SigmundSignatureArtifactGenerator(Collection<Artifact> artifacts, Predicate<Artifact> signable, Sigmund sigmund) {
        this.artifacts = new ArrayList<>(artifacts);
        this.signable = signable;
        this.sigmund = sigmund;
    }

    @Override
    public String generatorId() {
        return SigmundSignatureArtifactGeneratorFactory.NAME;
    }

    @Override
    public synchronized Collection<? extends Artifact> generate(Collection<? extends Artifact> generatedArtifacts) {
        artifacts.addAll(generatedArtifacts);
        if (artifacts.stream().anyMatch(SigmundSignatureArtifactGenerator::isSignature)) {
            LOGGER.debug("Signatures are present among artifacts, Sigmund does not sign");
            return List.of();
        }
        Signer signer = sigmund.signer();
        List<Artifact> signatures = new ArrayList<>();
        for (Artifact artifact : artifacts) {
            if (signable.test(artifact)) {
                for (SignedFile signed : signer.sign(artifact.getPath(), outputDirectory(signatures.size())).files()) {
                    signatures.add(new SubArtifact(artifact, "*", "*" + signed.fileExtension(), signed.path()));
                }
            }
        }
        LOGGER.info("Sigmund signed {} artifact(s)", signatures.size());
        return signatures;
    }

    private static boolean isSignature(Artifact artifact) {
        return artifact.getExtension().endsWith(".asc") || artifact.getExtension().endsWith(".sigstore.json");
    }

    private Path outputDirectory(int index) {
        try {
            if (signatureDirectory == null) {
                signatureDirectory = Files.createTempDirectory("sigmund-sign-");
            }
            return Files.createDirectories(signatureDirectory.resolve(String.valueOf(index)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public synchronized void close() {
        try {
            sigmund.close();
        } finally {
            deleteSignatures();
        }
    }

    private void deleteSignatures() {
        if (signatureDirectory == null) {
            return;
        }
        try (Stream<Path> paths = Files.walk(signatureDirectory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException e) {
            LOGGER.warn("Could not delete signatures in {}", signatureDirectory, e);
        }
        signatureDirectory = null;
    }
}
