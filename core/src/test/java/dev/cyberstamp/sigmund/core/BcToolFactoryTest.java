package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BcToolFactoryTest {

    @Test
    void toolName() {
        assertThat(new BcToolFactory().toolName()).isEqualTo("bc");
    }

    @Test
    void supportedCredentialTypes() {
        assertThat(new BcToolFactory().supportedCredentialTypes())
                .isEqualTo(Set.of("pgp4", "pgp6"));
    }

    @Test
    void createVerifyOnlyIsAvailable() {
        SignatureTool tool = new BcToolFactory().createVerifyOnly(Map.of());
        assertThat(tool.isAvailable()).isTrue();
        assertThat(tool.canSign()).isFalse();
        assertThat(tool.name()).isEqualTo("bc");
    }

    @Test
    void createVerifyOnlyWithCustomPaths() {
        SignatureTool tool = new BcToolFactory().createVerifyOnly(Map.of(
                "gnupg-home", "/tmp/gnupg",
                "cert-d-home", "/tmp/cert-d",
                "bc-private-home", "/tmp/bc-private"));
        assertThat(tool.isAvailable()).isTrue();
    }

    @Test
    void certDDefaultsToTheStoreSqUses() {
        assertThat(BcToolFactory.resolveCertDHome(Map.of()))
                .isEqualTo(Path.of(System.getProperty("user.home"), ".local", "share", "pgp.cert.d"));
    }

    @Test
    void privateKeysDefaultOutsideTheSharedCertD() {
        Path certD = BcToolFactory.resolveCertDHome(Map.of());
        Path privateHome = BcToolFactory.resolveBcPrivateHome(Map.of());

        assertThat(privateHome).isEqualTo(
                Path.of(System.getProperty("user.home"), ".local", "share", "sigmund", "bc-private"));
        assertThat(privateHome.startsWith(certD)).isFalse();
    }

    @Test
    void privateKeysStayPutWhenOnlyTheCertDMoves() {
        assertThat(BcToolFactory.resolveBcPrivateHome(Map.of("cert-d-home", "/tmp/cert-d")))
                .isEqualTo(BcToolFactory.resolveBcPrivateHome(Map.of()));
    }

    @Test
    void configuredPathsWin() {
        assertThat(BcToolFactory.resolveCertDHome(Map.of("cert-d-home", "/tmp/cert-d")))
                .isEqualTo(Path.of("/tmp/cert-d"));
        assertThat(BcToolFactory.resolveBcPrivateHome(Map.of("bc-private-home", "/tmp/bc-private")))
                .isEqualTo(Path.of("/tmp/bc-private"));
    }

    @Test
    void createWithSigningFingerprint() {
        SignatureTool tool = new BcToolFactory().createSigning(Map.of(
                "signing-fingerprint", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"), null);
        assertThat(tool.canSign()).isTrue();
    }

    // --- resolveSigningKeyBytes (custom env var path) ---

    @Test
    void resolveSigningKeyBytesFromCustomEnvVar() {
        String keyData = "key-content";
        byte[] result = BcToolFactory.resolveSigningKeyBytes(
                Map.of("signing-key-env", "MY_KEY"),
                name -> "MY_KEY".equals(name) ? keyData : null);
        assertThat(result).isEqualTo(keyData.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void resolveSigningKeyBytesThrowsWhenCustomEnvVarNotSet() {
        assertThatThrownBy(() -> BcToolFactory.resolveSigningKeyBytes(
                Map.of("signing-key-env", "MY_KEY"), name -> null))
                .isInstanceOf(SigmundException.class);
    }

    @Test
    void resolveSigningKeyBytesThrowsWhenCustomEnvVarEmpty() {
        assertThatThrownBy(() -> BcToolFactory.resolveSigningKeyBytes(
                Map.of("signing-key-env", "MY_KEY"),
                name -> "MY_KEY".equals(name) ? "" : null))
                .isInstanceOf(SigmundException.class);
    }

    // --- Ephemeral signing key round-trip (the SIGMUND_BC_SIGNING_KEY code path) ---

    @Test
    void ephemeralKeySignAndVerifyRoundTrip(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                tempDir.resolve("bc-private"));
        String fingerprint;
        try (BcRunner generator = new BcRunner(store, null, null)) {
            fingerprint = generator.generateKey("CI <ci@example.com>", "ed25519", null);
        }

        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        byte[] armoredKey = armorSecretKey(ring);

        try (BcRunner signer = new BcRunner(store, null, null,
                armoredKey, null, null)) {
            assertThat(signer.canSign()).isTrue();

            Path artifact = tempDir.resolve("artifact.jar");
            Files.writeString(artifact, "test artifact content");
            Path sigFile = tempDir.resolve("artifact.jar.asc");

            SignResult signResult = signer.sign(artifact, sigFile);
            assertThat(signResult.algorithm()).isNotNull();
            assertThat(Files.exists(sigFile)).isTrue();

            String armored = Files.readString(sigFile);
            OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
            OpenPgpClaim claim = new OpenPgpClaim(
                    armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

            VerifyResult result = signer.verify(artifact, claim);
            assertThat(result.isVerified()).isTrue();
        }
    }

    @Test
    void ephemeralKeyOnlyBcInSigner(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                tempDir.resolve("bc-private"));
        String fingerprint;
        try (BcRunner generator = new BcRunner(store, null, null)) {
            fingerprint = generator.generateKey("CI <ci@example.com>", "ed25519", null);
        }

        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        byte[] armoredKey = armorSecretKey(ring);

        BcRunner bcSigner = new BcRunner(store, null, null,
                armoredKey, null, null);

        Signer signer = new Signer(List.of(bcSigner), null);

        Path artifact = tempDir.resolve("artifact.jar");
        Files.writeString(artifact, "signer test");

        SigningOutput output = signer.sign(artifact, tempDir);
        assertThat(output.files().size()).isEqualTo(1);
        assertThat(output.files().get(0).toolName()).isEqualTo("bc");
    }

    private static byte[] armorSecretKey(PGPSecretKeyRing ring) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
            ring.encode(armored);
        }
        return out.toByteArray();
    }
}
