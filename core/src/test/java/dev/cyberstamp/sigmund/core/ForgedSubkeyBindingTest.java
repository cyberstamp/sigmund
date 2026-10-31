package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * A signing subkey proves its certificate's primary key only through a valid binding.
 *
 * <p>
 * The attack: take a victim's certificate and attach the attacker's own signing subkey, whose
 * only binding signature was made by the attacker's primary key and does not verify for the
 * victim's. A backend that trusts the certificate's structure instead of its binding
 * signatures attributes the attacker's signatures to the victim's primary key — so a policy
 * pinning the victim's fingerprint accepts an artifact the victim never signed. Getting the
 * crafted certificate into a key store takes a keyserver that does not validate uploads, or
 * a manual import; that is exactly what must not be able to change what is accepted.
 */
class ForgedSubkeyBindingTest {

    @TempDir
    Path dir;

    @Nested
    class BouncyCastle {

        @Test
        void aSubkeyBoundByAnotherKeyDoesNotProveTheVictimsPrimary() throws Exception {
            Keys keys = Keys.generate();
            Path artifact = Files.writeString(dir.resolve("artifact.txt"), "attacker content");
            OpenPgpClaim claim = keys.signWithAttackerSubkey(artifact);

            BcKeyStore store = new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc"));
            store.addFetched(keys.forgedCertificate(), "hkps://lenient.keyserver.example");
            try (BcRunner bc = new BcRunner(store, null, null)) {
                VerifyResult result = bc.verify(artifact, claim);

                assertThat(result.isVerified()).isFalse();
                assertThat(OpenPgpCredentials.from(result))
                        .doesNotContain(KeyCredential.openPgp(keys.victimFingerprint()));
            }
        }

        @Test
        void aValidlyBoundSubkeyProvesItselfAndItsPrimary() throws Exception {
            Keys keys = Keys.generate();
            Path artifact = Files.writeString(dir.resolve("artifact.txt"), "attacker content");
            OpenPgpClaim claim = keys.signWithAttackerSubkey(artifact);

            BcKeyStore store = new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc"));
            store.addFetched(keys.attackerCertificate(), "hkps://keys.example.org");
            try (BcRunner bc = new BcRunner(store, null, null)) {
                VerifyResult result = bc.verify(artifact, claim);

                assertThat(result.isVerified()).isTrue();
                assertThat(OpenPgpCredentials.from(result)).containsExactlyInAnyOrder(
                        KeyCredential.openPgp(keys.attackerSubkeyFingerprint()),
                        KeyCredential.openPgp(keys.attackerFingerprint()));
            }
        }
    }

    @Nested
    class EveryBackend {

        @Test
        @DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
        @DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
        void noBackendAttributesTheSignatureToTheVictim() throws Exception {
            Keys keys = Keys.generate();
            Path artifact = Files.writeString(dir.resolve("artifact.txt"), "attacker content");
            OpenPgpClaim claim = keys.signWithAttackerSubkey(artifact);
            String forged = armor(keys.forgedCertificate());

            BcKeyStore store = new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc"));
            store.addFetched(keys.forgedCertificate(), "hkps://lenient.keyserver.example");
            Path gpgHome = GpgTestKeys.home(dir.resolve("gpg-home"));
            Path sqHome = Files.createDirectories(dir.resolve("sq-home"));
            Path certFile = Files.writeString(dir.resolve("forged.asc"), forged);
            CliTool.run(Map.of("GNUPGHOME", gpgHome.toString()),
                    "gpg", "--batch", "--import", certFile.toString());
            CliTool.run(Map.of("SEQUOIA_HOME", sqHome.toString()),
                    "sq", "cert", "import", certFile.toString());

            try (BcRunner bc = new BcRunner(store, null, null)) {
                Map<String, VerifyResult> results = Map.of(
                        "bc", bc.verify(artifact, claim),
                        "gpg", new GpgRunner("gpg", null, gpgHome.toString()).verify(artifact, claim),
                        "sq", new SqRunner(sqHome).verify(artifact, claim));

                results.forEach((backend, result) -> {
                    assertThat(result.isVerified()).as(backend + " verified a forged binding").isFalse();
                    assertThat(OpenPgpCredentials.from(result))
                            .as(backend + " attributed the signature to the victim")
                            .doesNotContain(KeyCredential.openPgp(keys.victimFingerprint()));
                });
            }
        }
    }

    /**
     * A victim key, an attacker key with a signing subkey, and the forged certificate that
     * attaches the attacker's subkey to the victim's primary key.
     */
    private record Keys(PGPSecretKeyRing victim, PGPSecretKeyRing attacker) {

        static Keys generate() throws Exception {
            return new Keys(keyRing("Victim <victim@example.org>", false),
                    keyRing("Attacker <attacker@example.org>", true));
        }

        PGPPublicKeyRing forgedCertificate() {
            List<PGPPublicKey> keys = new ArrayList<>();
            keys.add(victim.getPublicKey());
            keys.add(attackerSubkey().getPublicKey());
            return new PGPPublicKeyRing(keys);
        }

        PGPPublicKeyRing attackerCertificate() {
            List<PGPPublicKey> keys = new ArrayList<>();
            Iterator<PGPPublicKey> it = attacker.getPublicKeys();
            while (it.hasNext()) {
                keys.add(it.next());
            }
            return new PGPPublicKeyRing(keys);
        }

        String victimFingerprint() {
            return hex(victim.getPublicKey().getFingerprint());
        }

        String attackerFingerprint() {
            return hex(attacker.getPublicKey().getFingerprint());
        }

        String attackerSubkeyFingerprint() {
            return hex(attackerSubkey().getPublicKey().getFingerprint());
        }

        OpenPgpClaim signWithAttackerSubkey(Path artifact) throws Exception {
            PGPSecretKey subkey = attackerSubkey();
            PGPSignatureGenerator generator = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(subkey.getPublicKey().getAlgorithm(),
                            HashAlgorithmTags.SHA256),
                    subkey.getPublicKey());
            generator.init(PGPSignature.BINARY_DOCUMENT, subkey.extractPrivateKey(null));
            PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
            hashed.setSignatureCreationTime(true, new Date());
            hashed.setIssuerFingerprint(false, subkey.getPublicKey());
            generator.setHashedSubpackets(hashed.generate());
            generator.update(Files.readAllBytes(artifact));
            String armored = armor(generator.generate());
            OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
            return new OpenPgpClaim(armored, info.version(), info.issuerFingerprint(),
                    info.algorithmId(), info.creationTime());
        }

        private PGPSecretKey attackerSubkey() {
            Iterator<PGPSecretKey> keys = attacker.getSecretKeys();
            keys.next();
            return keys.next();
        }
    }

    private static PGPSecretKeyRing keyRing(String userId, boolean withSigningSubkey)
            throws Exception {
        PGPKeyPair primary = ecdsaKeyPair();
        PGPSignatureSubpacketGenerator primaryFlags = new PGPSignatureSubpacketGenerator();
        primaryFlags.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        PGPKeyRingGenerator generator = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, primary, userId,
                new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1),
                primaryFlags.generate(), null,
                new JcaPGPContentSignerBuilder(primary.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(0).build(null));
        if (withSigningSubkey) {
            PGPSignatureSubpacketGenerator subkeyFlags = new PGPSignatureSubpacketGenerator();
            subkeyFlags.setKeyFlags(false, KeyFlags.SIGN_DATA);
            generator.addSubKey(ecdsaKeyPair(), subkeyFlags.generate(), null,
                    new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA,
                            HashAlgorithmTags.SHA256));
        }
        return generator.generateSecretKeyRing();
    }

    private static PGPKeyPair ecdsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec("P-256"), new SecureRandom());
        return new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.ECDSA,
                generator.generateKeyPair(), new Date());
    }

    private static String armor(PGPPublicKeyRing ring) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (OutputStream out = new ArmoredOutputStream(bytes)) {
            ring.encode(out);
        }
        return bytes.toString();
    }

    private static String armor(PGPSignature signature) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (OutputStream out = new ArmoredOutputStream(bytes)) {
            signature.encode(out);
        }
        return bytes.toString();
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().withUpperCase().formatHex(bytes);
    }
}
