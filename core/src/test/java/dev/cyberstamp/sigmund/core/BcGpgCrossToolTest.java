package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * Cross-tool interoperability tests between BC and GPG.
 *
 * <p>
 * GPG only understands v4 keys (LibrePGP). BC generates v4 keys unless asked for
 * {@code pgp6} — Ed25519 in the legacy EdDSA form GPG reads — so each v4 suite signs with BC
 * and verifies with GPG. Ed448 is v6 only.
 *
 * <p>
 * gpg→bc tests work because BC can verify v4 signatures.
 */
@DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
class BcGpgCrossToolTest {

    @Test
    void gpgSignBcVerifyEd25519(@TempDir Path tempDir) throws Exception {
        Path gpgHome = GpgTestKeys.home(tempDir.resolve("gpg-home"));
        GpgTestKeys.generate(gpgHome, "GPG Test <gpg@test.example>", "ed25519");

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test GPG→BC ed25519");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        GpgRunner gpgRunner = new GpgRunner("gpg", null, gpgHome.toString());
        SigningTests.signWithOnlyKey(gpgRunner, artifact, sigFile);
        assertThat(Files.exists(sigFile)).isTrue();

        String armoredPubKey = exportGpgKey(gpgHome, "gpg@test.example");
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        importKeyIntoBcStore(bcStore, armoredPubKey);

        BcRunner bcRunner = new BcRunner(bcStore, null, null);
        VerifyResult result = verifyWithBc(bcRunner, artifact, sigFile);
        assertThat(result.isVerified())
                .as("BC verification of GPG Ed25519 signature failed").isTrue();
    }

    @Test
    void gpgSignBcVerifyRsa(@TempDir Path tempDir) throws Exception {
        Path gpgHome = GpgTestKeys.home(tempDir.resolve("gpg-home"));
        GpgTestKeys.generate(gpgHome, "GPG RSA <gpg-rsa@test.example>", "rsa4096");

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test GPG→BC rsa");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        GpgRunner gpgRunner = new GpgRunner("gpg", null, gpgHome.toString());
        SigningTests.signWithOnlyKey(gpgRunner, artifact, sigFile);

        String armoredPubKey = exportGpgKey(gpgHome, "gpg-rsa@test.example");
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        importKeyIntoBcStore(bcStore, armoredPubKey);

        BcRunner bcRunner = new BcRunner(bcStore, null, null);
        VerifyResult result = verifyWithBc(bcRunner, artifact, sigFile);
        assertThat(result.isVerified())
                .as("BC verification of GPG RSA signature failed").isTrue();
    }

    @Test
    void bcSignGpgVerifyEd25519(@TempDir Path tempDir) throws Exception {
        bcSignGpgVerify(tempDir, "ed25519", "BC Ed25519 <bc-ed25519@test.example>");
    }

    @Test
    void bcSignGpgVerifyRsa4096(@TempDir Path tempDir) throws Exception {
        bcSignGpgVerify(tempDir, "rsa4096", "BC RSA <bc-rsa@test.example>");
    }

    @Test
    void bcSignGpgVerifyNistp256(@TempDir Path tempDir) throws Exception {
        bcSignGpgVerify(tempDir, "nistp256", "BC ECDSA <bc-ecdsa@test.example>");
    }

    @Test
    void bcSignGpgVerifyNistp384(@TempDir Path tempDir) throws Exception {
        bcSignGpgVerify(tempDir, "nistp384", "BC P384 <bc-p384@test.example>");
    }

    /**
     * Signs with a BC-generated v4 key, verifies with GPG.
     */
    private void bcSignGpgVerify(Path tempDir, String cipherSuite, String userId) throws Exception {
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        BcRunner bcRunner = new BcRunner(bcStore, null, null);

        String fingerprint = bcRunner.generateKey(userId, cipherSuite, null);
        BcRunner bcSigner = new BcRunner(bcStore, fingerprint, null);

        String armoredCert = bcRunner.exportCert(fingerprint);

        Path gpgHome = GpgTestKeys.home(tempDir.resolve("gpg-home"));
        Path certFile = tempDir.resolve("bc-cert.asc");
        Files.writeString(certFile, armoredCert);
        CliTool.Result importResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--batch", "--import", certFile.toString());
        assertThat(importResult.exitCode())
                .as("GPG import of BC v4 cert failed: " + importResult.stderr()).isEqualTo(0);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test BC→GPG " + cipherSuite);
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        SigningTests.signWithOnlyKey(bcSigner, artifact, sigFile);

        CliTool.Result verifyResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--verify", sigFile.toString(), artifact.toString());
        assertThat(verifyResult.exitCode() == 0 || verifyResult.stderr().contains("Good signature"))
                .as("GPG verification of BC " + cipherSuite + " signature failed: " + verifyResult.stderr()).isTrue();
    }

    /**
     * Exports a public key from GPG as an armored string.
     */
    private String exportGpgKey(Path gpgHome, String uid) {
        CliTool.Result exportResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--batch", "--armor", "--export", uid);
        assertThat(exportResult.exitCode()).as("GPG export failed: " + exportResult.stderr()).isEqualTo(0);
        assertThat(exportResult.stdout().isEmpty()).as("GPG exported empty public key").isFalse();
        return exportResult.stdout();
    }

    /**
     * Creates a BC key store in a temp directory.
     */
    private BcKeyStore createBcKeyStore(Path tempDir) {
        return new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
    }

    /**
     * Imports an armored public key into a BC key store.
     */
    private void importKeyIntoBcStore(BcKeyStore store, String armoredKey) throws Exception {
        try (InputStream in = PGPUtil.getDecoderStream(
                new ByteArrayInputStream(armoredKey.getBytes()))) {
            PGPPublicKeyRing keyRing = new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
            store.storeCert(keyRing);
        }
    }

    /**
     * Verifies a signature file with BC.
     */
    private VerifyResult verifyWithBc(BcRunner runner, Path artifact, Path sigFile) throws Exception {
        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        assertThat(info.version() > 0).as("Failed to parse signature packet").isTrue();

        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);
        return runner.verify(artifact, claim);
    }
}
