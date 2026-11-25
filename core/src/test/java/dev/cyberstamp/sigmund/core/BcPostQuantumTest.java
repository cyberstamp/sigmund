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
 * Bouncy Castle and {@code sq} on the post-quantum signatures of RFC 9980, in both directions:
 * Bouncy Castle verifies the ML-DSA composite signatures {@code sq} makes, and {@code sq} verifies
 * the ML-DSA and SLH-DSA signatures Bouncy Castle makes, each agreeing with the other on the
 * outcome and the key proved. ML-DSA keys are generated and signed with here; the SLH-DSA
 * signatures, slow to make, are fixtures Bouncy Castle made (see the {@code post-quantum} test
 * resources). {@link #bouncyCastleReadsAnMlDsaCertificate()} pins the library's support.
 *
 * <p>
 * {@code sq} runs under Sigmund's crypto policy, as it does in a build, which keeps Sequoia's
 * built-in defaults for SLH-DSA; a host policy such as Fedora's may reject SLH-DSA outright.
 */
@DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
class BcPostQuantumTest {

    private static final String ML_DSA_65 = "mldsa65-ed25519";
    private static final String ML_DSA_87 = "mldsa87-ed448";
    private static final String SLH_DSA_128S = "slhdsa128s";
    private static final String SLH_DSA_128F = "slhdsa128f";
    private static final String SLH_DSA_256S = "slhdsa256s";
    private static final List<String> SLH_DSA_SUITES = List.of(SLH_DSA_128S, SLH_DSA_128F, SLH_DSA_256S);

    private static final Map<String, String> ALGORITHM_NAMES = Map.of(
            ML_DSA_65, "ML-DSA-65+Ed25519",
            ML_DSA_87, "ML-DSA-87+Ed448",
            SLH_DSA_128S, "SLH-DSA-SHAKE-128s",
            SLH_DSA_128F, "SLH-DSA-SHAKE-128f",
            SLH_DSA_256S, "SLH-DSA-SHAKE-256s");

    private static Path sqHome;
    private static Map<String, String> fingerprints;
    private static BcKeyStore bcKeys;
    private static Map<String, String> bcFingerprints;

    @BeforeAll
    static void generatePqcKeys(@TempDir Path tempDir) throws Exception {
        sqHome = Files.createDirectories(tempDir.resolve("sq-home"));
        SqRunner sq = new SqRunner(sqHome);
        fingerprints = Map.of(
                ML_DSA_65, sq.generateKey("PQC 65 <pqc65@sigmund.example>", ML_DSA_65, "rfc9580"),
                ML_DSA_87, sq.generateKey("PQC 87 <pqc87@sigmund.example>", ML_DSA_87, "rfc9580"));
        bcKeys = new BcKeyStore(null, tempDir.resolve("bc-cert-d"), tempDir.resolve("bc-private"));
        bcFingerprints = Map.of(
                ML_DSA_65, BcTestKeys.generate(bcKeys, "BC 65 <bc65@sigmund.example>", ML_DSA_65, Credential.TYPE_PGP6),
                ML_DSA_87, BcTestKeys.generate(bcKeys, "BC 87 <bc87@sigmund.example>", ML_DSA_87, Credential.TYPE_PGP6));
        try (BcRunner exporter = new BcRunner(bcKeys, null, null)) {
            for (String fingerprint : bcFingerprints.values()) {
                importIntoSq(Files.writeString(tempDir.resolve(fingerprint + ".asc"), exporter.exportCert(fingerprint)));
            }
        }
        for (String suite : SLH_DSA_SUITES) {
            Path cert = fixture(suite + ".cert.asc", tempDir);
            bcKeys.storeCert(parsed(Files.readAllBytes(cert)));
            importIntoSq(cert);
        }
    }

    private static void importIntoSq(Path cert) {
        CliTool.run(Map.of("SEQUOIA_HOME", sqHome.toString()), "sq", "cert", "import", cert.toString());
    }

    /** Copies a {@code post-quantum} test resource to a file. */
    private static Path fixture(String name, Path dir) throws Exception {
        try (InputStream in = BcPostQuantumTest.class.getResourceAsStream("/post-quantum/" + name)) {
            assertThat(in).as(name).isNotNull();
            return Files.write(dir.resolve(name), in.readAllBytes());
        }
    }

    private static PGPPublicKeyRing parsed(byte[] armored) throws Exception {
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored))) {
            return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
        }
    }

    @Test
    void bouncyCastleReadsAnMlDsaCertificate() throws Exception {
        assertThat(certificateOf(ML_DSA_87).getPublicKey().getAlgorithm()).isEqualTo(31);
    }

    /**
     * The fingerprints {@link KeyRingFiles} computes from a v6 certificate's packets, which it
     * relies on to report a certificate Bouncy Castle cannot parse for its own keys only, are the
     * ones Bouncy Castle computes.
     */
    @Test
    void theKeysOfAnMlDsaCertificateAreReadFromItsPackets() throws Exception {
        PGPPublicKeyRing ring = certificateOf(ML_DSA_87);
        List<String> parsed = new ArrayList<>();
        ring.getPublicKeys().forEachRemaining(key -> parsed.add(KeyRingFiles.hex(key.getFingerprint())));

        assertThat(KeyRingFiles.keyFingerprints(ring.getEncoded()))
                .containsExactlyElementsOf(parsed)
                .contains(fingerprints.get(ML_DSA_87))
                .hasSizeGreaterThan(1);
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

    @ParameterizedTest
    @ValueSource(strings = { ML_DSA_65, ML_DSA_87 })
    void aPostQuantumSignatureBcMakesIsVerifiedBySqAndBcAlike(String suite, @TempDir Path dir) throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        OpenPgpClaim claim = claimOf(signWithBc(suite, artifact, dir));
        assertAgreeOnAVerifiedSignature(suite, artifact, claim, bcFingerprints.get(suite));
    }

    /** The signature Bouncy Castle made with each SLH-DSA key is kept as a fixture. */
    @ParameterizedTest
    @ValueSource(strings = { SLH_DSA_128S, SLH_DSA_128F, SLH_DSA_256S })
    void anSlhDsaSignatureBcMadeIsVerifiedBySqAndBcAlike(String suite, @TempDir Path dir) throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        OpenPgpClaim claim = claimOf(fixture(suite + ".sig.asc", dir));
        String primary = KeyRingFiles.hex(parsed(Files.readAllBytes(fixture(suite + ".cert.asc", dir))).getPublicKey()
                .getFingerprint());
        assertAgreeOnAVerifiedSignature(suite, artifact, claim, primary);
    }

    @ParameterizedTest
    @ValueSource(strings = { SLH_DSA_128S, SLH_DSA_128F, SLH_DSA_256S })
    void aTamperedArtifactFailsAnSlhDsaSignatureBcMadeInSqAndBcAlike(String suite, @TempDir Path dir)
            throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "tampered");
        OpenPgpClaim claim = claimOf(fixture(suite + ".sig.asc", dir));

        try (BcRunner runner = new BcRunner(bcKeys, null, null)) {
            assertThat(runner.verify(artifact, claim).isFailed()).isTrue();
        }
        assertThat(new SqRunner(sqHome).verify(artifact, claim).isFailed()).isTrue();
    }

    private static void assertAgreeOnAVerifiedSignature(String suite, Path artifact, OpenPgpClaim claim,
            String primaryFingerprint) {
        OpenPgpVerifyResult bc;
        try (BcRunner runner = new BcRunner(bcKeys, null, null)) {
            bc = (OpenPgpVerifyResult) runner.verify(artifact, claim);
        }
        OpenPgpVerifyResult sq = (OpenPgpVerifyResult) new SqRunner(sqHome).verify(artifact, claim);

        assertThat(bc.isVerified()).as(bc.detail()).isTrue();
        assertThat(sq.isVerified()).as(sq.detail()).isTrue();
        assertThat(bc.algorithm()).isEqualTo(ALGORITHM_NAMES.get(suite));
        assertThat(bc.signerIdentifier()).isEqualTo(sq.signerIdentifier());
        assertThat(bc.primaryFingerprint()).isEqualTo(sq.primaryFingerprint()).isEqualTo(primaryFingerprint);
    }

    @ParameterizedTest
    @ValueSource(strings = { ML_DSA_65, ML_DSA_87 })
    void aTamperedArtifactFailsAPostQuantumSignatureBcMakesInSqAndBcAlike(String suite, @TempDir Path dir)
            throws Exception {
        Path artifact = Files.writeString(dir.resolve("artifact.jar"), "post-quantum");
        OpenPgpClaim claim = claimOf(signWithBc(suite, artifact, dir));
        Files.writeString(artifact, "tampered");

        try (BcRunner runner = new BcRunner(bcKeys, null, null)) {
            assertThat(runner.verify(artifact, claim).isFailed()).isTrue();
        }
        assertThat(new SqRunner(sqHome).verify(artifact, claim).isFailed()).isTrue();
    }

    private static Path signWithBc(String suite, Path artifact, Path dir) {
        Path signature = dir.resolve("artifact.jar.asc");
        try (BcRunner signer = new BcRunner(bcKeys, bcFingerprints.get(suite), null)) {
            SigningTests.signWithOnlyKey(signer, artifact, signature);
        }
        return signature;
    }

    private static PGPPublicKeyRing certificateOf(String suite) throws Exception {
        byte[] armored = new SqRunner(sqHome).exportCert(fingerprints.get(suite)).getBytes(StandardCharsets.US_ASCII);
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored))) {
            return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
        }
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
