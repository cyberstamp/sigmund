package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BcRunnerSignerInspectionTest {

    @TempDir
    Path tempDir;

    private BcRunner createRunner(boolean resolveSigners, List<String> keyservers) {
        Path certD = tempDir.resolve("cert-d");
        try {
            Files.createDirectories(certD);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        BcKeyStore store = new BcKeyStore(null, certD,
                tempDir.resolve("bc-private"));
        KeyserverFetcher fetcher = resolveSigners && !keyservers.isEmpty()
                ? new KeyserverFetcher(store, keyservers)
                : null;
        return new BcRunner(store, null, null, null, null, fetcher);
    }

    @Test
    void canInspectKeyCredential() {
        try (BcRunner runner = createRunner(false, List.of())) {
            assertThat(runner.canInspect(
                    new KeyCredential("pgp4", "AABB000000000000000000000000000000000000"))).isTrue();
        }
    }

    @Test
    void canInspectAnEmailIdentity() {
        try (BcRunner runner = createRunner(false, List.of())) {
            assertThat(runner.canInspect(IdentityCredential.email(null, "a@b.com"))).isTrue();
        }
    }

    @Test
    void cannotInspectAWorkflowIdentity() {
        try (BcRunner runner = createRunner(false, List.of())) {
            assertThat(runner.canInspect(
                    new IdentityCredential("https://issuer", Map.of(IdentityCredential.SUBJECT, "subject"))))
                    .isFalse();
        }
    }

    @Test
    void inspectLocalStoreNotFoundReturnsPerSourceResults() {
        try (BcRunner runner = createRunner(false, List.of())) {
            var results = runner.inspect(
                    new KeyCredential("pgp4",
                            "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"));
            assertThat(results.isEmpty()).isFalse();
            assertThat(results.stream().allMatch(r -> !r.found())).isTrue();
            assertThat(results.stream().anyMatch(
                    r -> r.sourceLabel().startsWith(TrustRootRef.KIND_OPENPGP_CERT_D + " "))).isTrue();
        }
    }
}
