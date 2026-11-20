package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * What Bouncy Castle does with a post-quantum signature, against keys and signatures made by
 * {@code sq}: since 1.87 it reads ML-DSA composite keys and verifies their signatures, agreeing
 * with {@code sq}. {@link #bouncyCastleReadsAnMlDsaCertificate()} pins the library's support.
 */
@DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
class BcPostQuantumTest {

    private static final String ML_DSA_65 = "mldsa65-ed25519";
    private static final String ML_DSA_87 = "mldsa87-ed448";

    private static final Map<String, String> ALGORITHM_NAMES = Map.of(
            ML_DSA_65, "ML-DSA-65+Ed25519",
            ML_DSA_87, "ML-DSA-87+Ed448");

    private static Path sqHome;
    private static Map<String, String> fingerprints;

    @BeforeAll
    static void generatePqcKeys(@TempDir Path tempDir) throws Exception {
        sqHome = Files.createDirectories(tempDir.resolve("sq-home"));
        SqRunner sq = new SqRunner(sqHome);
        fingerprints = Map.of(
                ML_DSA_65, sq.generateKey("PQC 65 <pqc65@sigmund.example>", ML_DSA_65, "rfc9580"),
                ML_DSA_87, sq.generateKey("PQC 87 <pqc87@sigmund.example>", ML_DSA_87, "rfc9580"));
    }

    @Test
    void bouncyCastleReadsAnMlDsaCertificate() throws Exception {
        byte[] certificate = new SqRunner(sqHome).exportCert(fingerprints.get(ML_DSA_87))
                .getBytes(StandardCharsets.US_ASCII);

        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(certificate))) {
            PGPPublicKeyRing ring = new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
            assertThat(ring.getPublicKey().getAlgorithm()).isEqualTo(31);
        }
    }

    @Test
    void anMlDsaCertificateIsReadFromTheStore(@TempDir Path dir) throws Exception {
        Path file = Files.writeString(dir.resolve("cert.asc"),
                new SqRunner(sqHome).exportCert(fingerprints.get(ML_DSA_87)));
        List<UnreadableCertificate> unreadable = new ArrayList<>();

        assertThat(KeyRingFiles.readCertificate(file, TrustRootRef.unknown(), Set.of(), unreadable)).isNotNull();
        assertThat(unreadable).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = { ML_DSA_65, ML_DSA_87 })
    void aPostQuantumSignatureIsVerifiedByBcAlone(String suite, @TempDir Path dir) throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        Path signature = signWithSq(suite, artifact, dir);

        ClaimResult result = verifyWithBcAlone(suite, artifact, signature, dir);

        assertThat(result.outcome()).isEqualTo(ClaimOutcome.VERIFIED);
        assertThat(result.verifiedBy()).isEqualTo("bc");
        assertThat(result.algorithm()).isEqualTo(ALGORITHM_NAMES.get(suite));
    }

    @ParameterizedTest
    @ValueSource(strings = { ML_DSA_65, ML_DSA_87 })
    void aTamperedArtifactFailsAPostQuantumSignatureInBc(String suite, @TempDir Path dir) throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        Path signature = signWithSq(suite, artifact, dir);
        Files.writeString(artifact, "tampered");

        ClaimResult result = verifyWithBcAlone(suite, artifact, signature, dir);

        assertThat(result.outcome()).isEqualTo(ClaimOutcome.FAILED);
        assertThat(result.verifiedBy()).isEqualTo("bc");
    }

    @ParameterizedTest
    @ValueSource(strings = { ML_DSA_65, ML_DSA_87 })
    void bcAndSqProveTheSameKeyForAPostQuantumSignature(String suite, @TempDir Path dir) throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        OpenPgpClaim claim = claimOf(signWithSq(suite, artifact, dir));

        OpenPgpVerifyResult bc;
        try (BcRunner runner = new BcRunner(bcStore(suite, dir), null, null)) {
            bc = (OpenPgpVerifyResult) runner.verify(artifact, claim);
        }
        OpenPgpVerifyResult sq = (OpenPgpVerifyResult) new SqRunner(sqHome).verify(artifact, claim);

        assertThat(bc.isVerified()).isTrue();
        assertThat(sq.isVerified()).isTrue();
        assertThat(bc.signerIdentifier()).isEqualTo(sq.signerIdentifier());
        assertThat(bc.primaryFingerprint()).isEqualTo(sq.primaryFingerprint()).isEqualTo(fingerprints.get(suite));
    }

    private static Path signWithSq(String suite, Path artifact, Path dir) {
        Path signature = dir.resolve("artifact.jar.asc");
        SigningTests.signWithOnlyKey(new SqRunner("sq", sqHome, fingerprints.get(suite)), artifact, signature);
        return signature;
    }

    private static ClaimResult verifyWithBcAlone(String suite, Path artifact, Path signature, Path dir)
            throws Exception {
        try (BcRunner bc = new BcRunner(bcStore(suite, dir), null, null);
                Sigmund sigmund = Sigmund.builder()
                        .verificationConfig(new VerificationConfig(false, false, List.of(), List.of("bc")))
                        .addTool(bc)
                        .build()) {
            return sigmund.verify(artifact, signature).files().get(0).results().get(0);
        }
    }

    private static OpenPgpClaim claimOf(Path signature) throws Exception {
        String armored = Files.readString(signature);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        return new OpenPgpClaim(armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);
    }

    private static BcKeyStore bcStore(String suite, Path dir) throws Exception {
        String fingerprint = fingerprints.get(suite);
        Path certD = dir.resolve("cert-d");
        String lower = fingerprint.toLowerCase();
        Path certFile = certD.resolve(lower.substring(0, 2)).resolve(lower.substring(2));
        Files.createDirectories(certFile.getParent());
        Files.writeString(certFile, new SqRunner(sqHome).exportCert(fingerprint));
        return new BcKeyStore(null, certD, dir.resolve("bc-private"));
    }
}
