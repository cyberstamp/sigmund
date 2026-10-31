package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

class GpgRunnerTest {

    @Test
    void validSigCarriesSigningAndPrimaryFingerprints() {
        String status = """
                [GNUPG:] NEWSIG
                [GNUPG:] GOODSIG 1111111111111111 Alice <alice@example.org>
                [GNUPG:] VALIDSIG 1111111111111111111111111111111111111111 2026-09-30 1790000000 0 4 0 22 10 00 4aee18f83afdeb23468b2e5a2d7baf3c1e9f5a12
                """;

        String[] validSig = GpgRunner.validSigFields(status);

        assertThat(GpgRunner.fingerprintField(validSig, GpgRunner.VALIDSIG_SIGNING_FINGERPRINT))
                .isEqualTo("1111111111111111111111111111111111111111");
        assertThat(GpgRunner.fingerprintField(validSig, GpgRunner.VALIDSIG_PRIMARY_FINGERPRINT))
                .isEqualTo("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
    }

    @Test
    void validSigWithoutAPrimaryFingerprintHasNone() {
        String[] validSig = GpgRunner.validSigFields(
                "[GNUPG:] VALIDSIG 1111111111111111111111111111111111111111 2026-09-30 1790000000 0 4 0 22 10 00");

        assertThat(GpgRunner.fingerprintField(validSig, GpgRunner.VALIDSIG_PRIMARY_FINGERPRINT)).isNull();
    }

    @Test
    void noValidSigWhenTheSignatureIsBad() {
        String[] validSig = GpgRunner.validSigFields("[GNUPG:] BADSIG 1111111111111111 Alice");

        assertThat(validSig).isNull();
        assertThat(GpgRunner.fingerprintField(validSig, GpgRunner.VALIDSIG_SIGNING_FINGERPRINT)).isNull();
    }

    @Test
    void extractGpgKeyIdFromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractGpgKeyId(stderr)).isEqualTo("4AEE18F83AFDEB23");
    }

    @Test
    void extractGpgKeyIdLongForm() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractGpgKeyId(stderr)).isEqualTo("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
    }

    @Test
    void extractGpgKeyIdNotFound() {
        assertThat(GpgRunner.extractGpgKeyId("gpg: some other output\n")).isNull();
    }

    @Test
    void extractGpgKeyIdNullInput() {
        assertThat(GpgRunner.extractGpgKeyId(null)).isNull();
    }

    // --- extractSignerUserId ---

    @Test
    void extractSignerUserIdFromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User Name <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractSignerUserId(stderr)).isEqualTo("User Name <user@example.com>");
    }

    @Test
    void extractSignerUserIdNoGoodSignature() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Can't check signature: No public key
                """;
        assertThat(GpgRunner.extractSignerUserId(stderr)).isNull();
    }

    @Test
    void extractSignerUserIdNullInput() {
        assertThat(GpgRunner.extractSignerUserId(null)).isNull();
    }

    // --- extractAlgorithm ---

    @Test
    void extractAlgorithmRsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractAlgorithm(stderr)).isEqualTo("RSA");
    }

    @Test
    void extractAlgorithmEddsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using EDDSA key ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertThat(GpgRunner.extractAlgorithm(stderr)).isEqualTo("EDDSA");
    }

    @Test
    void extractAlgorithmNullInput() {
        assertThat(GpgRunner.extractAlgorithm(null)).isNull();
    }

    @Test
    void extractAlgorithmNotFound() {
        assertThat(GpgRunner.extractAlgorithm("gpg: some other output\n")).isNull();
    }

    // --- parseColonsSigningInfo ---

    @Test
    void parseColonsPublicKey() {
        String output = """
                pub:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                uid:u::::1669154062::HASH::Alice <alice@example.com>::::::::::0:
                sub:u:4096:1:84EFABB1BAFB7050:1669154062::::::e::::::23:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.toolName()).isEqualTo("gpg");
        assertThat(info.fingerprint()).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        assertThat(info.algorithm()).isEqualTo("RSA");
        assertThat(info.userId()).isEqualTo("Alice <alice@example.com>");
        assertThat(info.credentialType()).isEqualTo("pgp4");
    }

    @Test
    void parseColonsSecretKey() {
        String output = """
                sec:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                uid:u::::1669154062::HASH::Bob <bob@example.com>::::::::::0:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.fingerprint()).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        assertThat(info.algorithm()).isEqualTo("RSA");
        assertThat(info.userId()).isEqualTo("Bob <bob@example.com>");
    }

    @Test
    void parseColonsEddsaKey() {
        String output = """
                pub:u:255:22:AABBCCDD11223344:1700000000:::u:::scESC::::::23::0:
                fpr:::::::::AABBCCDD11223344AABBCCDD11223344AABBCCDD:
                uid:u::::1700000000::HASH::Ed User <ed@example.com>::::::::::0:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.fingerprint()).isEqualTo("AABBCCDD11223344AABBCCDD11223344AABBCCDD");
        assertThat(info.algorithm()).isEqualTo("EdDSA");
        assertThat(info.userId()).isEqualTo("Ed User <ed@example.com>");
    }

    @Test
    void parseColonsEmptyOutput() {
        SigningInfo info = GpgRunner.parseColonsSigningInfo("");
        assertThat(info.toolName()).isEqualTo("gpg");
        assertThat(info.fingerprint()).isNull();
        assertThat(info.algorithm()).isNull();
        assertThat(info.userId()).isNull();
    }

    @Test
    void parseColonsNoUidLine() {
        String output = """
                pub:u:4096:1:6A7F5DB1C68BDB81:1669154062:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                """;
        SigningInfo info = GpgRunner.parseColonsSigningInfo(output);
        assertThat(info.fingerprint()).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        assertThat(info.algorithm()).isEqualTo("RSA");
        assertThat(info.userId()).isNull();
    }

    @Test
    void aNamedSubkeyKeepsItsFingerprintWhenTheListingStartsWithThePrimary() {
        String subkey = "AABBCCDD11223344AABBCCDD11223344AABBCCDD";
        String output = """
                sec:u:255:22:1111111111111111:1700000000:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                uid:u::::1700000000::HASH::Ed User <ed@example.com>::::::::::0:
                ssb:u:255:22:AABBCCDD11223344:1700000000::::::s::::::23:
                fpr:::::::::AABBCCDD11223344AABBCCDD11223344AABBCCDD:
                """;
        SigningInfo info = GpgRunner.namedSigningInfo(subkey, output);
        assertThat(info.fingerprint()).isEqualTo(subkey);
        assertThat(info.userId()).isEqualTo("Ed User <ed@example.com>");
        assertThat(info.credentialType()).isEqualTo("pgp4");
    }

    @Test
    void aNamedSubkeyReportsItsOwnAlgorithmRatherThanThePrimarys() {
        String subkey = "AABBCCDD11223344AABBCCDD11223344AABBCCDD";
        String output = """
                sec:u:4096:1:6A7F5DB1C68BDB81:1700000000:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                uid:u::::1700000000::HASH::Ed User <ed@example.com>::::::::::0:
                ssb:u:255:22:AABBCCDD11223344:1700000000::::::s::::::23:
                fpr:::::::::aabbccdd11223344aabbccdd11223344aabbccdd:
                """;
        SigningInfo info = GpgRunner.namedSigningInfo(subkey, output);
        assertThat(info.algorithm()).isEqualTo("EdDSA");
    }

    @Test
    void aNamedPrimaryKeyReportsItsOwnAlgorithmRatherThanItsSubkeys() {
        String primary = "41A2197725BD63EB00D071D46A7F5DB1C68BDB81";
        String output = """
                sec:u:4096:1:6A7F5DB1C68BDB81:1700000000:::u:::scESC::::::23::0:
                fpr:::::::::41A2197725BD63EB00D071D46A7F5DB1C68BDB81:
                ssb:u:255:22:AABBCCDD11223344:1700000000::::::s::::::23:
                fpr:::::::::AABBCCDD11223344AABBCCDD11223344AABBCCDD:
                """;
        SigningInfo info = GpgRunner.namedSigningInfo(primary, output);
        assertThat(info.algorithm()).isEqualTo("RSA");
    }

    @Test
    void aNamedKeyIsTypedFromItsFingerprintWhenListingFails() {
        GpgRunner gpg = new GpgRunner("false", "41A2197725BD63EB00D071D46A7F5DB1C68BDB81");

        List<SigningInfo> infos = gpg.signingInfo();

        assertThat(infos).hasSize(1);
        assertThat(infos.get(0).fingerprint()).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        assertThat(infos.get(0).credentialType()).isEqualTo("pgp4");
    }

    @Test
    void eachNamedKeyGetsAnEntryWhenListingFails() {
        GpgRunner gpg = new GpgRunner("false", List.of("41A2197725BD63EB00D071D46A7F5DB1C68BDB81",
                "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"), null, null, false, false, List.of());

        assertThat(gpg.signingInfo()).extracting(SigningInfo::fingerprint).containsExactly(
                "41A2197725BD63EB00D071D46A7F5DB1C68BDB81", "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
    }

    @Test
    void theDefaultKeyIsOfUnknownTypeWhenListingFails(@TempDir Path home) {
        GpgRunner gpg = new GpgRunner("false", null, home.toString());

        List<SigningInfo> infos = gpg.signingInfo();

        assertThat(infos).hasSize(1);
        assertThat(infos.get(0).credentialType()).isNull();
    }

    @Test
    void aKeyOutsideTheNamedOnesIsRejected(@TempDir Path dir) {
        GpgRunner gpg = new GpgRunner("false", "41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        String outside = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";

        assertThatThrownBy(() -> gpg.sign(dir.resolve("a.jar"), dir.resolve("a.jar.asc"),
                new SigningInfo("gpg", outside, null, null, "pgp4")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("gpg")
                .hasMessageContaining(outside);
    }

    /**
     * A runner naming two keys signs with whichever key it is given.
     */
    @Nested
    @DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
    class MultipleKeys {

        @TempDir
        Path dir;

        @Test
        void eachKeySignsWithItself() throws IOException {
            String fp1 = generate("One <one@example.com>");
            String fp2 = generate("Two <two@example.com>");
            GpgRunner runner = new GpgRunner("gpg", List.of(fp1, fp2), home().toString(), null,
                    false, false, List.of());

            List<SigningInfo> keys = runner.signingInfo();

            assertThat(keys).extracting(SigningInfo::fingerprint).containsExactly(fp1, fp2);
            for (SigningInfo key : keys) {
                assertThat(provenBy(runner, key)).contains(KeyCredential.openPgp(key.fingerprint()));
            }
        }

        private List<Credential> provenBy(GpgRunner runner, SigningInfo key) throws IOException {
            Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
            Path signature = dir.resolve("artifact-" + key.fingerprint() + ".asc");
            runner.sign(artifact, signature, key);
            Claim claim = new OpenPgpSignatureFormat()
                    .parse(Evidence.read(signature, Evidence.SOURCE_SIDECAR)).get(0);
            return runner.extractCredentials(runner.verify(artifact, claim));
        }

        private Path home() {
            return dir.resolve("gpg-home");
        }

        private String generate(String userId) throws IOException {
            return GpgTestKeys.generate(home(), userId, "ed25519");
        }

    }

    // --- canSign ---

    @Test
    void signingCapableRunnerCanSign() {
        var runner = new GpgRunner("gpg", List.of(), null,
                null, true, false, false, List.of());
        assertThat(runner.canSign()).isTrue();
    }

    @Test
    void verifyOnlyRunnerCannotSign() {
        var runner = new GpgRunner("gpg", List.of(), null,
                null, false, false, false, List.of());
        assertThat(runner.canSign()).isFalse();
    }

    @Test
    void defaultConstructorCanSign() {
        var runner = new GpgRunner();
        assertThat(runner.canSign()).isTrue();
    }

    // --- parseDefaultKey ---

    @TempDir
    Path tempDir;

    @Test
    void parseDefaultKeyFound() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key ABCD1234ABCD1234\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyWithComments() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                # This is a comment
                keyserver hkps://keys.openpgp.org

                # default-key OLD_KEY
                default-key 41A2197725BD63EB00D071D46A7F5DB1C68BDB81
                """);
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
    }

    @Test
    void parseDefaultKeyLastWins() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                default-key FIRST_KEY
                default-key SECOND_KEY
                """);
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("SECOND_KEY");
    }

    @Test
    void parseDefaultKeyNotPresent() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, """
                keyserver hkps://keys.openpgp.org
                auto-key-locate local,wkd
                """);
        assertThat(GpgRunner.parseDefaultKey(conf)).isNull();
    }

    @Test
    void parseDefaultKeyFileNotFound() {
        assertThat(GpgRunner.parseDefaultKey(tempDir.resolve("nonexistent.conf"))).isNull();
    }

    @Test
    void parseDefaultKeyNullPath() {
        assertThat(GpgRunner.parseDefaultKey(null)).isNull();
    }

    @Test
    void parseDefaultKeyQuoted() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key \"ABCD1234ABCD1234\"\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyHexPrefix() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key 0xABCD1234ABCD1234\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyExactSubkeyMarker() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key ABCD1234ABCD1234!\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyQuotedHexPrefixAndExclamation() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key \"0xABCD1234ABCD1234!\"\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    @Test
    void parseDefaultKeyTabDelimiter() throws IOException {
        Path conf = tempDir.resolve("gpg.conf");
        Files.writeString(conf, "default-key\tABCD1234ABCD1234\n");
        assertThat(GpgRunner.parseDefaultKey(conf)).isEqualTo("ABCD1234ABCD1234");
    }

    /**
     * The verdict read from GnuPG's {@code --status-fd} lines, as GnuPG 2.4 writes them; the
     * agreement tests run the same cases against the installed gpg.
     */
    @Nested
    class VerdictFromStatus {

        private static final String VALIDSIG = "[GNUPG:] VALIDSIG"
                + " 8746E44B15EE4052D2A645981900992082AE2A13 2026-10-16 1792178762 0 4 0 1 8 00"
                + " 8746E44B15EE4052D2A645981900992082AE2A13\n";

        @Test
        void aGoodSignatureVerifies() {
            assertThat(GpgRunner.verdict("[GNUPG:] GOODSIG 1900992082AE2A13 Signer\n" + VALIDSIG))
                    .isEqualTo(ToolVerdict.verified());
        }

        @Test
        void aBadSignatureFails() {
            assertThat(GpgRunner.verdict("[GNUPG:] BADSIG 1900992082AE2A13 Signer\n"
                    + "[GNUPG:] FAILURE gpg-exit 33554433\n")).isEqualTo(ToolVerdict.failed());
        }

        /** GnuPG exits 0 for a revoked key's signature; only the status line says it is revoked. */
        @Test
        void aRevokedKeyFails() {
            assertThat(GpgRunner.verdict("[GNUPG:] REVKEYSIG 6737F201BB02FA7A Signer\n" + VALIDSIG
                    + "[GNUPG:] KEYREVOKED\n")).isEqualTo(ToolVerdict.failed());
        }

        @Test
        void aKeyThatHadExpiredWhenItSignedFails() {
            assertThat(GpgRunner.verdict("[GNUPG:] KEYEXPIRED 1791401161\n"
                    + "[GNUPG:] EXPKEYSIG C1E9F7FDDA6AAB67 Signer\n" + VALIDSIG))
                    .isEqualTo(ToolVerdict.failed());
        }

        /** A signature made while the key was valid stays valid after the key expires (§3.8). */
        @Test
        void aKeyThatExpiredAfterItSignedVerifies() {
            assertThat(GpgRunner.verdict("[GNUPG:] KEYEXPIRED 1800000000\n"
                    + "[GNUPG:] EXPKEYSIG C1E9F7FDDA6AAB67 Signer\n" + VALIDSIG))
                    .isEqualTo(ToolVerdict.verified());
        }

        @Test
        void aMissingKeyIsNotAvailable() {
            assertThat(GpgRunner.verdict("[GNUPG:] ERRSIG F9F37B1217967E91 1 8 00 1792178762 9"
                    + " 4C31CD7C37B62BB8A83B7FEBF9F37B1217967E91\n"
                    + "[GNUPG:] NO_PUBKEY F9F37B1217967E91\n"))
                    .isEqualTo(ToolVerdict.indeterminate(IndeterminateReason.KEY_UNAVAILABLE));
        }

        @Test
        void anAlgorithmGnupgDoesNotSupportIsUnsupported() {
            assertThat(GpgRunner.verdict("[GNUPG:] ERRSIG F9F37B1217967E91 99 8 00 1792178762 4"
                    + " 4C31CD7C37B62BB8A83B7FEBF9F37B1217967E91\n"))
                    .isEqualTo(ToolVerdict.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM));
        }

        @Test
        void statusWithoutAVerdictIsTheToolsFailure() {
            assertThat(GpgRunner.verdict("[GNUPG:] FAILURE gpg-exit 33554433\n"))
                    .isEqualTo(ToolVerdict.indeterminate(IndeterminateReason.TOOL_UNAVAILABLE));
        }
    }
}
