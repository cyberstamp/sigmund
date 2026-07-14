package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

/**
 * Cross-tool interoperability tests between BC and GPG.
 *
 * <p>
 * GPG only understands v4 keys (LibrePGP), so bc→gpg tests are only
 * possible when BC generates v4 keys (e.g. ECDSA/NIST P-curves, which
 * use the JCA fallback). BC-generated Ed25519/Ed448/RSA keys are v6 and
 * cannot be imported by GPG.
 *
 * <p>
 * gpg→bc tests work because BC can verify v4 signatures.
 */
@EnabledIf("gpgAvailable")
class BcGpgCrossToolTest {

    static boolean gpgAvailable() {
        return GpgRunner.isToolAvailable();
    }

    @Test
    void gpgSignBcVerifyEd25519(@TempDir Path tempDir) throws Exception {
        Path gpgHome = createGpgHome(tempDir);

        CliTool.Result genResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--batch", "--passphrase", "", "--pinentry-mode", "loopback",
                "--quick-gen-key", "--yes",
                "GPG Test <gpg@test.example>", "ed25519", "sign", "0");
        assertEquals(0, genResult.exitCode(),
                "GPG key generation failed: " + genResult.stderr());

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test GPG→BC ed25519");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        GpgRunner gpgRunner = new GpgRunner("gpg", null, gpgHome.toString());
        gpgRunner.sign(artifact, sigFile);
        assertTrue(Files.exists(sigFile));

        String armoredPubKey = exportGpgKey(gpgHome, "gpg@test.example");
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        importKeyIntoBcStore(bcStore, armoredPubKey);

        BcRunner bcRunner = new BcRunner(bcStore, null, null);
        VerifyResult result = verifyWithBc(bcRunner, artifact, sigFile);
        assertEquals(Verdict.PASS, result.verdict(),
                "BC verification of GPG Ed25519 signature failed");
    }

    @Test
    void gpgSignBcVerifyRsa(@TempDir Path tempDir) throws Exception {
        Path gpgHome = createGpgHome(tempDir);

        CliTool.Result genResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--batch", "--passphrase", "", "--pinentry-mode", "loopback",
                "--quick-gen-key", "--yes",
                "GPG RSA <gpg-rsa@test.example>", "rsa4096", "sign", "0");
        assertEquals(0, genResult.exitCode(),
                "GPG key generation failed: " + genResult.stderr());

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test GPG→BC rsa");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        GpgRunner gpgRunner = new GpgRunner("gpg", null, gpgHome.toString());
        gpgRunner.sign(artifact, sigFile);

        String armoredPubKey = exportGpgKey(gpgHome, "gpg-rsa@test.example");
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        importKeyIntoBcStore(bcStore, armoredPubKey);

        BcRunner bcRunner = new BcRunner(bcStore, null, null);
        VerifyResult result = verifyWithBc(bcRunner, artifact, sigFile);
        assertEquals(Verdict.PASS, result.verdict(),
                "BC verification of GPG RSA signature failed");
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
     * Signs with BC (v4 ECDSA key), verifies with GPG.
     */
    private void bcSignGpgVerify(Path tempDir, String cipherSuite, String userId) throws Exception {
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        BcRunner bcRunner = new BcRunner(bcStore, null, null);

        String fingerprint = bcRunner.generateKey(userId, cipherSuite);
        BcRunner bcSigner = new BcRunner(bcStore, fingerprint, null);

        String armoredCert = bcRunner.exportCert(fingerprint);

        Path gpgHome = createGpgHome(tempDir);
        Path certFile = tempDir.resolve("bc-cert.asc");
        Files.writeString(certFile, armoredCert);
        CliTool.Result importResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--batch", "--import", certFile.toString());
        assertEquals(0, importResult.exitCode(),
                "GPG import of BC v4 cert failed: " + importResult.stderr());

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test BC→GPG " + cipherSuite);
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        bcSigner.sign(artifact, sigFile);

        CliTool.Result verifyResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--verify", sigFile.toString(), artifact.toString());
        assertTrue(verifyResult.exitCode() == 0 || verifyResult.stderr().contains("Good signature"),
                "GPG verification of BC " + cipherSuite + " signature failed: " + verifyResult.stderr());
    }

    /**
     * Creates a temp GPG home directory with proper permissions.
     */
    private Path createGpgHome(Path tempDir) throws Exception {
        Path gpgHome = tempDir.resolve("gpg-home");
        Files.createDirectories(gpgHome);
        Files.setPosixFilePermissions(gpgHome, PosixFilePermissions.fromString("rwx------"));
        return gpgHome;
    }

    /**
     * Exports a public key from GPG as an armored string.
     */
    private String exportGpgKey(Path gpgHome, String uid) {
        CliTool.Result exportResult = CliTool.run(
                Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--batch", "--armor", "--export", uid);
        assertEquals(0, exportResult.exitCode(), "GPG export failed: " + exportResult.stderr());
        assertFalse(exportResult.stdout().isEmpty(), "GPG exported empty public key");
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
        assertTrue(info.version() > 0, "Failed to parse signature packet");

        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId());
        return runner.verify(artifact, unit);
    }
}
