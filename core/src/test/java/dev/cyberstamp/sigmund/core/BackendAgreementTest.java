package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

/**
 * Checks that the OpenPGP backends agree about the same claim.
 *
 * <p>
 * Disagreement here would be a real defect rather than a curiosity: the configured toolchain
 * decides which backend answers first, so two backends reaching different outcomes would mean
 * a {@code toolchain} setting — an argument, not policy — changes whether an artifact is
 * accepted, which §5.3 forbids.
 *
 * <p>
 * A NIST P-curve key is used because Bouncy Castle emits v4 keys for those, and GnuPG cannot
 * import the v6 keys it emits for Ed25519.
 */
@EnabledIf("bothCliToolsAvailable")
class BackendAgreementTest {

    static boolean bothCliToolsAvailable() {
        return GpgRunner.isToolAvailable() && SqRunner.isToolAvailable();
    }

    /** What one backend concluded, named so a disagreement report is readable. */
    private record Answer(String backend, ClaimOutcome outcome, IndeterminateReason reason) {
    }

    @Nested
    class Agreement {

        @Test
        void aValidSignatureVerifiesEverywhere(@TempDir Path dir) throws Exception {
            Fixture fixture = Fixture.signed(dir, "agreed content");

            assertThat(fixture.answers())
                    .allSatisfy(answer -> assertThat(answer.outcome())
                            .as(answer.backend() + " disagreed")
                            .isEqualTo(ClaimOutcome.VERIFIED));
        }

        @Test
        void aTamperedArtifactFailsEverywhere(@TempDir Path dir) throws Exception {
            Fixture fixture = Fixture.signed(dir, "original content");
            Files.writeString(fixture.artifact, "tampered content");

            assertThat(fixture.answers())
                    .allSatisfy(answer -> assertThat(answer.outcome())
                            .as(answer.backend() + " disagreed")
                            .isEqualTo(ClaimOutcome.FAILED));
        }

        @Test
        void anUnavailableKeyIsIndeterminateEverywhere(@TempDir Path dir) throws Exception {
            Fixture fixture = Fixture.signedWithoutPublishingTheKey(dir, "unknown signer");

            assertThat(fixture.answers())
                    .allSatisfy(answer -> {
                        assertThat(answer.outcome())
                                .as(answer.backend() + " should not decide without the key")
                                .isEqualTo(ClaimOutcome.INDETERMINATE);
                        assertThat(answer.reason())
                                .as(answer.backend() + " reason")
                                .isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
                    });
        }
    }

    /**
     * A signing key published to every backend's store, an artifact, and its signature.
     */
    private static final class Fixture {

        private final Path artifact;
        private final Path signature;
        private final BcRunner bc;
        private final GpgRunner gpg;
        private final SqRunner sq;

        private Fixture(Path artifact, Path signature, BcRunner bc, GpgRunner gpg, SqRunner sq) {
            this.artifact = artifact;
            this.signature = signature;
            this.bc = bc;
            this.gpg = gpg;
            this.sq = sq;
        }

        static Fixture signed(Path dir, String content) throws Exception {
            return build(dir, content, true);
        }

        static Fixture signedWithoutPublishingTheKey(Path dir, String content) throws Exception {
            return build(dir, content, false);
        }

        private static Fixture build(Path dir, String content, boolean publishKey)
                throws Exception {
            BcKeyStore signingStore = new BcKeyStore(null, dir.resolve("signing-cert-d"),
                    dir.resolve("signing-private"));
            String fingerprint = new BcRunner(signingStore, null, null)
                    .generateKey("Agreement Test <agreement@test.example>", "nistp256");

            Path artifact = Files.writeString(dir.resolve("artifact.txt"), content);
            Path signature = dir.resolve("artifact.txt.asc");
            new BcRunner(signingStore, fingerprint, null).sign(artifact, signature);

            Path gpgHome = Files.createDirectories(dir.resolve("gpg-home"));
            Files.setPosixFilePermissions(gpgHome, PosixFilePermissions.fromString("rwx------"));
            Path sqHome = Files.createDirectories(dir.resolve("sq-home"));

            BcKeyStore verifyingStore = new BcKeyStore(null, dir.resolve("verify-cert-d"),
                    dir.resolve("verify-private"));
            if (publishKey) {
                String armoredCert = new BcRunner(signingStore, null, null)
                        .exportCert(fingerprint);
                publishToBc(verifyingStore, armoredCert);
                publishToGpg(gpgHome, dir, armoredCert);
                publishToSq(sqHome, dir, armoredCert);
            }

            return new Fixture(artifact, signature,
                    new BcRunner(verifyingStore, null, null),
                    new GpgRunner("gpg", null, gpgHome.toString()),
                    new SqRunner(sqHome));
        }

        private static void publishToBc(BcKeyStore store, String armoredCert) throws Exception {
            try (InputStream in = PGPUtil.getDecoderStream(
                    new ByteArrayInputStream(armoredCert.getBytes()))) {
                store.storeCert(new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator()));
            }
        }

        private static void publishToGpg(Path gpgHome, Path dir, String armoredCert)
                throws Exception {
            Path certFile = Files.writeString(dir.resolve("cert-for-gpg.asc"), armoredCert);
            CliTool.run(Map.of("GNUPGHOME", gpgHome.toString()),
                    "gpg", "--batch", "--import", certFile.toString());
        }

        private static void publishToSq(Path sqHome, Path dir, String armoredCert)
                throws Exception {
            Path certFile = Files.writeString(dir.resolve("cert-for-sq.asc"), armoredCert);
            CliTool.run(Map.of("SEQUOIA_HOME", sqHome.toString()),
                    "sq", "cert", "import", certFile.toString());
        }

        List<Answer> answers() throws Exception {
            OpenPgpClaim claim = claim();
            List<Answer> answers = new ArrayList<>(3);
            answers.add(answer("bc", bc.verify(artifact, claim)));
            answers.add(answer("gpg", gpg.verify(artifact, claim)));
            answers.add(answer("sq", sq.verify(artifact, claim)));
            return answers;
        }

        private OpenPgpClaim claim() throws Exception {
            String armored = Files.readString(signature);
            OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
            return new OpenPgpClaim(armored, info.version(), info.issuerFingerprint(),
                    info.algorithmId(), info.creationTime());
        }

        private static Answer answer(String backend, VerifyResult result) {
            return new Answer(backend, result.outcome(), result.reason());
        }
    }
}
