package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * What Bouncy Castle does with a post-quantum signature, against a key and signature made by
 * {@code sq}.
 *
 * <p>
 * Bouncy Castle 1.87 reads ML-DSA keys, but {@link BcRunner#canVerify(Claim)} still declines
 * post-quantum signatures, so a block only BC is asked about is set aside.
 */
@DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
class BcPostQuantumTest {

    private static Path sqHome;
    private static String fingerprint;

    @BeforeAll
    static void generatePqcKey(@TempDir Path tempDir) throws Exception {
        sqHome = tempDir.resolve("sq-home");
        Files.createDirectories(sqHome);
        fingerprint = new SqRunner(sqHome).generateKey("PQC Test <test@sigmund.example>",
                SqRunner.DEFAULT_CIPHER_SUITE, "rfc9580");
    }

    private Path storeInCertD(Path dir) throws Exception {
        Path certD = dir.resolve("cert-d");
        String lower = fingerprint.toLowerCase();
        Path certFile = certD.resolve(lower.substring(0, 2)).resolve(lower.substring(2));
        Files.createDirectories(certFile.getParent());
        Files.writeString(certFile, new SqRunner(sqHome).exportCert(fingerprint));
        return certD;
    }

    /**
     * BC alone, with the certificate in the store it reads: the block is set aside as no installed
     * tool's to check, permanently, rather than reported as a key to go and find.
     */
    @Test
    void aPostQuantumBlockCheckedByBcAloneIsUnsupported(@TempDir Path dir) throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        Path signature = dir.resolve("artifact.jar.asc");
        SigningTests.signWithOnlyKey(new SqRunner("sq", sqHome, fingerprint), artifact, signature);
        BcKeyStore store = new BcKeyStore(null, storeInCertD(dir), dir.resolve("bc-private"));

        try (BcRunner bc = new BcRunner(store, null, null);
                Sigmund sigmund = Sigmund.builder().verificationConfig(
                        new VerificationConfig(false, false, List.of(), List.of("bc")))
                        .addTool(bc).build()) {

            ClaimResult result = sigmund.verify(artifact, signature).files().get(0).results().get(0);

            assertThat(result.isIndeterminateBecause(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
            assertThat(result.verifiedBy()).as("no tool was asked").isNull();
            assertThat(result.algorithm()).isEqualTo("ML-DSA-87+Ed448");
        }
    }
}
