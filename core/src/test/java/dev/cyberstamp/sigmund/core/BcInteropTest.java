package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Bouncy Castle signs with a key of every cipher suite and key version it generates, and
 * verifies the signature: the artifact as signed verifies, and the same signature over altered
 * bytes fails.
 */
class BcInteropTest {

    @TempDir
    Path tempDir;

    @ParameterizedTest
    @CsvSource({ "ed25519, pgp4", "ed25519, pgp6", "ed448, pgp6", "rsa4096, pgp4", "rsa4096, pgp6" })
    void aSignatureVerifiesOverTheArtifactAndFailsOverAlteredBytes(String cipherSuite, String credentialType)
            throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        String fingerprint = BcTestKeys.generate(store, "Test <test@example.com>", cipherSuite, credentialType);
        Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "original content");
        Path signature = tempDir.resolve("artifact.txt.asc");

        try (BcRunner signer = new BcRunner(store, fingerprint, null)) {
            SignResult signed = SigningTests.signWithOnlyKey(signer, artifact, signature);
            OpenPgpClaim claim = claimOf(signature);

            assertThat(signed.algorithm()).isNotNull();
            assertThat(claim.packetVersion()).isEqualTo(Credential.TYPE_PGP6.equals(credentialType) ? 6 : 4);
            assertThat(signer.verify(artifact, claim).isVerified()).isTrue();

            Files.writeString(artifact, "tampered content");

            assertThat(signer.verify(artifact, claim).isFailed()).isTrue();
        }
    }

    private static OpenPgpClaim claimOf(Path signature) throws Exception {
        String armored = Files.readString(signature);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        return new OpenPgpClaim(armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);
    }
}
