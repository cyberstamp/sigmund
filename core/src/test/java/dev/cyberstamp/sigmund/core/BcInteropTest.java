package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class BcInteropTest {

    @TempDir
    Path tempDir;

    @ParameterizedTest
    @ValueSource(strings = { "ed25519", "ed448", "rsa4096" })
    void signAndVerifyRoundTrip(String cipherSuite) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null);

        String fp = runner.generateKey("Test <test@example.com>", cipherSuite);
        BcRunner signer = new BcRunner(store, fp, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "hello world");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        SignResult signResult = signer.sign(artifact, sigFile);
        assertThat(signResult.algorithm()).isNotNull();
        assertThat(Files.exists(sigFile)).isTrue();

        String armored = Files.readString(sigFile);
        assertThat(armored.contains("-----BEGIN PGP SIGNATURE-----")).isTrue();

        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        assertThat(info.version() > 0).isTrue();

        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

        VerifyResult result = signer.verify(artifact, claim);
        assertThat(result.isVerified()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = { "ed25519", "ed448", "rsa4096" })
    void tamperedArtifactFailsVerification(String cipherSuite) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null);

        String fp = runner.generateKey("Test <test@example.com>", cipherSuite);
        BcRunner signer = new BcRunner(store, fp, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "original content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        // tamper with artifact
        Files.writeString(artifact, "tampered content");

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

        VerifyResult result = signer.verify(artifact, claim);
        assertThat(result.isFailed()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = { "ed25519", "ed448", "rsa4096" })
    void sigmundBuilderDiscoversBc(String cipherSuite) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner bcRunner = new BcRunner(store, null, null);

        String fp = bcRunner.generateKey("Test <test@example.com>", cipherSuite);
        BcRunner signer = new BcRunner(store, fp, null);

        try (Sigmund sigmund = Sigmund.builder()
                .addTool(signer)
                .build()) {

            assertThat(sigmund.tool("bc")).isNotNull();
            assertThat(sigmund.tool("bc").isAvailable()).isTrue();
        }
    }
}
