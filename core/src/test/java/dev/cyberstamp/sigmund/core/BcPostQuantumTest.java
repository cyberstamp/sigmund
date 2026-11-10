package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * What Bouncy Castle does with a post-quantum signature, against a key and signature made by
 * {@code sq}.
 *
 * <p>
 * Bouncy Castle 1.86 cannot read an ML-DSA key, so {@link BcRunner#canVerify(Claim)} declines
 * post-quantum signatures. {@link #bouncyCastleCannotReadAnMlDsaCertificate()} pins the library's
 * limitation: when an upgrade reads such keys it fails, and BC can start verifying them.
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

    @Test
    void bouncyCastleCannotReadAnMlDsaCertificate() {
        byte[] certificate = new SqRunner(sqHome).exportCert(fingerprint).getBytes(StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> {
            try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(certificate))) {
                new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
            }
        }).hasMessageContaining("unknown signature key algorithm");
    }

    /**
     * So a certificate Bouncy Castle cannot parse is reported only for the keys it holds: the
     * v6 fingerprints are computed from the packets, which needs no knowledge of ML-DSA.
     */
    @Test
    void theKeysOfAnMlDsaCertificateAreReadFromItsPackets(@TempDir Path dir) throws Exception {
        Path file = Files.writeString(dir.resolve("cert.asc"), new SqRunner(sqHome).exportCert(fingerprint));
        List<UnreadableCertificate> unreadable = new ArrayList<>();

        assertThat(KeyRingFiles.readCertificate(file, TrustRootRef.unknown(), Set.of(), unreadable)).isNull();

        assertThat(unreadable).singleElement().satisfies(certificate -> {
            assertThat(certificate.keys()).contains(fingerprint).hasSizeGreaterThan(1);
            assertThat(certificate.cause()).isEqualTo(UnreadableCertificate.Cause.UNKNOWN_ALGORITHM);
        });
    }

    /**
     * Asked directly, past {@link BcRunner#canVerify(Claim)}: a copy of the key it cannot read is
     * reported as such, not as a key to go and find.
     */
    @Test
    void anMlDsaCertificateInTheStoreIsReportedAsUnreadable(@TempDir Path dir) throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        Path signature = dir.resolve("artifact.jar.asc");
        SigningTests.signWithOnlyKey(new SqRunner("sq", sqHome, fingerprint), artifact, signature);
        Path certD = storeInCertD(dir);
        String armored = Files.readString(signature);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);

        try (BcRunner bc = new BcRunner(new BcKeyStore(null, certD, dir.resolve("bc-private")), null, null)) {
            VerifyResult result = bc.verify(artifact, new OpenPgpClaim(armored, info.version(),
                    info.issuerFingerprint(), info.algorithmId(), null));

            assertThat(result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
            assertThat(result.reasonDetail()).isEqualTo("Bouncy Castle cannot read the copy from " + certD
                    + ": unknown signature key algorithm: " + info.algorithmId());
        }
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
