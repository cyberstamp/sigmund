package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Checks that the OpenPGP backends agree about keys whose validity, not whose signature, is in
 * question, and that only an attack signal reads as one.
 *
 * <p>
 * {@link ClaimOutcome#FAILED} is the attack signal and blocks every build. A key bound by a
 * SHA-1 self-signature is how many release keys on Maven Central are still bound, and a
 * certificate served without its user IDs is what keys.openpgp.org publishes for a key whose
 * owner never verified an address; neither says the artifact's bytes differ from what was
 * signed. A revoked key and a key that had expired when it signed do mean the signature must
 * not be trusted, and stay {@code FAILED}. Since the configured toolchain decides which backend
 * answers, all of them must reach the same outcome.
 *
 * <p>
 * Keys are RSA, the shape of the SHA-1-bound keys found in practice; GnuPG rejects a SHA-1
 * self-signature on a NIST P-256 key for its hash size alone.
 */
@DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
@DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
class KeyValidityAgreementTest {

    private static final Duration DAY = Duration.ofDays(1);

    @TempDir
    Path dir;

    @ParameterizedTest(name = "bound {0}")
    @ValueSource(strings = { "2011-04-12T22:15:08Z", "now" })
    void aKeyBoundByASha1SelfSignatureVerifiesEverywhere(String boundAt) throws Exception {
        Instant created = "now".equals(boundAt) ? Instant.now().minus(DAY) : Instant.parse(boundAt);
        PGPSecretKeyRing key = keyRing(HashAlgorithmTags.SHA1, created, null);
        Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
        OpenPgpClaim claim = sign(key, artifact);

        assertThat(outcomes(publicRing(key), artifact, claim)).isEqualTo(everywhere("VERIFIED"));
    }

    @Test
    void aTamperedArtifactUnderASha1BoundKeyStillFailsEverywhere() throws Exception {
        PGPSecretKeyRing key = keyRing(HashAlgorithmTags.SHA1, Instant.now().minus(DAY), null);
        Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
        OpenPgpClaim claim = sign(key, artifact);
        Files.writeString(artifact, "tampered content");

        assertThat(outcomes(publicRing(key), artifact, claim)).isEqualTo(everywhere("FAILED"));
    }

    @Test
    void aCertificateWithoutUserIdsIsAKeyThatIsNotAvailableEverywhere() throws Exception {
        PGPSecretKeyRing key = keyRing(HashAlgorithmTags.SHA256, Instant.now().minus(DAY), null);
        Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
        OpenPgpClaim claim = sign(key, artifact);

        assertThat(outcomes(withoutUserIds(publicRing(key)), artifact, claim))
                .isEqualTo(everywhere("INDETERMINATE(" + IndeterminateReason.KEY_UNAVAILABLE + ")"));
    }

    @Test
    void aRevokedKeyFailsEverywhere() throws Exception {
        PGPSecretKeyRing key = keyRing(HashAlgorithmTags.SHA256, Instant.now().minus(DAY), null);
        Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
        OpenPgpClaim claim = sign(key, artifact);

        assertThat(outcomes(revoked(key), artifact, claim)).isEqualTo(everywhere("FAILED"));
    }

    @Test
    void aKeyThatExpiredBeforeItSignedFailsEverywhere() throws Exception {
        PGPSecretKeyRing key = keyRing(HashAlgorithmTags.SHA256, Instant.now().minus(DAY.multipliedBy(10)),
                DAY);
        Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
        OpenPgpClaim claim = sign(key, artifact);

        assertThat(outcomes(publicRing(key), artifact, claim)).isEqualTo(everywhere("FAILED"));
    }

    private static Map<String, String> everywhere(String outcome) {
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("bc", outcome);
        expected.put("gpg", outcome);
        expected.put("sq", outcome);
        return expected;
    }

    /** Each backend's outcome, with its reason where there is one, so a report shows all three. */
    private Map<String, String> outcomes(PGPPublicKeyRing cert, Path artifact, OpenPgpClaim claim)
            throws Exception {
        Map<String, String> outcomes = new LinkedHashMap<>();
        answers(cert, artifact, claim).forEach((backend, result) -> outcomes.put(backend,
                result.reason() == null
                        ? result.outcome().name()
                        : result.outcome() + "(" + result.reason() + ")"));
        return outcomes;
    }

    private Map<String, VerifyResult> answers(PGPPublicKeyRing cert, Path artifact,
            OpenPgpClaim claim) throws Exception {
        Path certFile = Files.writeString(dir.resolve("cert.asc"), armor(cert));

        BcKeyStore store = new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc"));
        store.addFetched(cert, "hkps://keys.example.org");
        Path gpgHome = GpgTestKeys.home(dir.resolve("gpg-home"));
        CliTool.run(Map.of("GNUPGHOME", gpgHome.toString()),
                "gpg", "--batch", "--import", certFile.toString());
        Path sqHome = Files.createDirectories(dir.resolve("sq-home"));
        CliTool.run(SqRunner.envFor(sqHome), "sq", "cert", "import", certFile.toString());

        Map<String, VerifyResult> answers = new LinkedHashMap<>();
        try (BcRunner bc = new BcRunner(store, null, null)) {
            answers.put("bc", bc.verify(artifact, claim));
        }
        answers.put("gpg", new GpgRunner("gpg", null, gpgHome.toString()).verify(artifact, claim));
        answers.put("sq", new SqRunner(sqHome).verify(artifact, claim));
        return answers;
    }

    /**
     * An RSA signing key created at the given time, its user ID bound by a self-signature made
     * then with the given hash, and expiring after the given lifetime when one is given.
     */
    private static PGPSecretKeyRing keyRing(int certificationHash, Instant created,
            Duration lifetime) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        generator.initialize(2048, new SecureRandom());
        PGPKeyPair primary = new JcaPGPKeyPair(PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.RSA_GENERAL, generator.generateKeyPair(), Date.from(created));
        PGPSignatureSubpacketGenerator binding = new PGPSignatureSubpacketGenerator();
        binding.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        binding.setSignatureCreationTime(true, Date.from(created));
        if (lifetime != null) {
            binding.setKeyExpirationTime(true, lifetime.toSeconds());
        }
        return new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primary,
                "Release Signer <release@example.org>",
                new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1),
                binding.generate(), null,
                new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, certificationHash),
                new JcePBESecretKeyEncryptorBuilder(0).build(null))
                .generateSecretKeyRing();
    }

    private static PGPPublicKeyRing publicRing(PGPSecretKeyRing secret) {
        return new PGPPublicKeyRing(List.of(secret.getPublicKey()));
    }

    /**
     * The certificate as keys.openpgp.org serves it for an unverified owner: the primary key
     * with its user IDs, and so their self-signatures, removed.
     */
    private static PGPPublicKeyRing withoutUserIds(PGPPublicKeyRing ring) {
        PGPPublicKey key = ring.getPublicKey();
        Iterator<byte[]> ids = key.getRawUserIDs();
        while (ids.hasNext()) {
            key = PGPPublicKey.removeCertification(key, ids.next());
        }
        return new PGPPublicKeyRing(List.of(key));
    }

    /**
     * The certificate with a key revocation for compromise, made an hour before now — after the
     * key was created and before anything is signed in a test.
     */
    private static PGPPublicKeyRing revoked(PGPSecretKeyRing key) throws Exception {
        PGPSecretKey secret = key.getSecretKey();
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256),
                secret.getPublicKey());
        generator.init(PGPSignature.KEY_REVOCATION, secret.extractPrivateKey(null));
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, Date.from(Instant.now().minus(Duration.ofHours(1))));
        hashed.setRevocationReason(true, RevocationReasonTags.KEY_COMPROMISED, "compromised");
        hashed.setIssuerFingerprint(false, secret.getPublicKey());
        generator.setHashedSubpackets(hashed.generate());
        PGPSignature revocation = generator.generateCertification(secret.getPublicKey());
        return new PGPPublicKeyRing(List.of(
                PGPPublicKey.addCertification(secret.getPublicKey(), revocation)));
    }

    private static OpenPgpClaim sign(PGPSecretKeyRing key, Path artifact) throws Exception {
        PGPSecretKey secret = key.getSecretKey();
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256),
                secret.getPublicKey());
        generator.init(PGPSignature.BINARY_DOCUMENT, secret.extractPrivateKey(null));
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, new Date());
        hashed.setIssuerFingerprint(false, secret.getPublicKey());
        generator.setHashedSubpackets(hashed.generate());
        generator.update(Files.readAllBytes(artifact));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (OutputStream out = new ArmoredOutputStream(bytes)) {
            generator.generate().encode(out);
        }
        String armored = bytes.toString();
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        return new OpenPgpClaim(armored, info.version(), info.issuerFingerprint(),
                info.algorithmId(), info.creationTime());
    }

    private static String armor(PGPPublicKeyRing ring) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (OutputStream out = new ArmoredOutputStream(bytes)) {
            ring.encode(out);
        }
        return bytes.toString();
    }
}
