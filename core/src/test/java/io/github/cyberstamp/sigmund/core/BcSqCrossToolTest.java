package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

/**
 * Cross-tool interoperability tests between BC and Sequoia (sq).
 *
 * <p>
 * Sequoia supports v6 keys (RFC 9580), so both bc→sq and sq→bc
 * round-trips work with v6 Ed25519 and RSA keys.
 */
@EnabledIf("sqAvailable")
class BcSqCrossToolTest {

    static boolean sqAvailable() {
        return SqRunner.isToolAvailable();
    }

    @Test
    void sqSignBcVerifyEd25519(@TempDir Path tempDir) throws Exception {
        Path sqHome = tempDir.resolve("sq-home");
        SqRunner sq = new SqRunner("sq", sqHome);

        String sqFp = sq.generateKey("SQ Test <sq@test.example>", "cv25519");
        SqRunner sqSigner = new SqRunner("sq", sqHome, sqFp);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test SQ→BC ed25519");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        sqSigner.sign(artifact, sigFile);

        String sqCert = sq.exportCert(sqFp);
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        importKeyIntoBcStore(bcStore, sqCert);

        BcRunner bcRunner = new BcRunner(bcStore, null, null);
        VerifyResult result = verifyWithBc(bcRunner, artifact, sigFile);
        assertEquals(Verdict.PASS, result.verdict(),
                "BC verification of SQ Ed25519 signature failed");
    }

    @Test
    void bcSignSqVerifyEd25519(@TempDir Path tempDir) throws Exception {
        BcKeyStore bcStore = createBcKeyStore(tempDir);
        BcRunner bcRunner = new BcRunner(bcStore, null, null);

        String bcFp = bcRunner.generateKey("BC Test <bc@test.example>", "ed25519");
        BcRunner bcSigner = new BcRunner(bcStore, bcFp, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "cross-tool test BC→SQ ed25519");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        bcSigner.sign(artifact, sigFile);

        String bcCert = bcRunner.exportCert(bcFp);
        Path sqHome = tempDir.resolve("sq-home");
        importCertIntoSq(sqHome, bcCert, tempDir);

        SqRunner sq = new SqRunner("sq", sqHome);
        Path certFile = sq.findCertFile(bcFp);
        assertNotNull(certFile, "SQ did not find the imported BC cert");

        // Debug: try sq verify directly and capture stderr
        CliTool.Result sqVerifyResult = CliTool.run(
                Map.of("SEQUOIA_HOME", sqHome.toString()),
                "sq", "--overwrite", "verify",
                "--signer-file", certFile.toString(),
                "--signature-file", sigFile.toString(),
                artifact.toString());
        assertEquals(0, sqVerifyResult.exitCode(),
                "SQ verification of BC Ed25519 signature failed: " + sqVerifyResult.stderr());
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
     * Imports an armored cert into Sequoia's cert store using sq cert import.
     */
    private void importCertIntoSq(Path sqHome, String armoredCert, Path tempDir) throws Exception {
        Path certFile = tempDir.resolve("bc-cert-for-sq.asc");
        Files.writeString(certFile, armoredCert);
        CliTool.Result result = CliTool.run(
                Map.of("SEQUOIA_HOME", sqHome.toString()),
                "sq", "--overwrite", "cert", "import", certFile.toString());
        assertEquals(0, result.exitCode(),
                "SQ cert import failed: " + result.stderr());
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
