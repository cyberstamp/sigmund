package dev.cyberstamp.sigmund.resolver.generator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.spi.artifact.generator.ArtifactGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class SigmundSignatureArtifactGenerator implements ArtifactGenerator {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final List<Artifact> artifacts;
    private final Predicate<Artifact> signableArtifactPredicate;
    private final AtomicBoolean closed;

    SigmundSignatureArtifactGenerator(Collection<Artifact> artifacts, Predicate<Artifact> signableArtifactPredicate) {
        this.artifacts = new ArrayList<>(artifacts);
        this.signableArtifactPredicate = signableArtifactPredicate;
        this.closed = new AtomicBoolean(false);
    }

    @Override
    public String generatorId() {
        return SigmundSignatureArtifactGeneratorFactory.NAME;
    }

    @Override
    public synchronized Collection<? extends Artifact> generate(Collection<? extends Artifact> generatedArtifacts) {
        // runs first among generators, so generatedArtifacts is empty; kept for a lower configured priority
        artifacts.addAll(generatedArtifacts);

        // back out if the build already attached signatures, e.g. maven-gpg-plugin or a Sigstore plugin
        if (artifacts.stream()
                .anyMatch(a -> a.getExtension().endsWith(".asc")
                        || a.getExtension().endsWith(".sigstore.json"))) {
            logger.debug("Signatures are present among artifacts, bailing out");
            return Collections.emptyList();
        }

        // sign relevant artifacts
        ArrayList<Artifact> result = new ArrayList<>();
        for (Artifact artifact : artifacts) {
            if (signableArtifactPredicate.test(artifact)) {
                // sign and add signature artifact (w/ file set) to list
                //   result.add(new SubArtifact(
                //     artifact,
                //     artifact.getClassifier(),
                //     artifact.getExtension() + ARTIFACT_EXTENSION,
                //     signatureTempFile.toFile()));
            }
        }
        logger.debug("Signed {} artifacts", result.size());
        return result;
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            // close
        }
    }
}
