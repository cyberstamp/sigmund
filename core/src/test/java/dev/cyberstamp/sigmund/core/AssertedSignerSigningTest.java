package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * Signs with real keys under a {@code signing.signer} assertion: a signature by the key the
 * signer pins is written, and one by any other key fails signing and writes nothing.
 */
class AssertedSignerSigningTest {

    private static final String OTHER_FP = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";

    @TempDir
    Path dir;

    @Nested
    class Bc {

        @Test
        void aPinnedKeyWritesTheSignature() throws IOException {
            String fp = generate();

            sign("bc", fp, settings(fp));

            assertThat(dir.resolve("out/lib-1.0.jar.asc")).exists();
        }

        @Test
        void anotherKeyFailsNamingBothAndWritesNothing() throws IOException {
            String fp = generate();

            assertMismatch("bc", fp, settings(fp));
        }

        @Test
        void aPinnedKeyFromATskFileOverEmptyStoresWritesTheSignature() throws Exception {
            String fp = generate();
            Path tsk = exportSecretKey(fp);

            sign("bc", fp, Map.of(
                    "gnupg-home", dir.resolve("empty/gnupg").toString(),
                    "cert-d-home", dir.resolve("empty/cert-d").toString(),
                    "bc-private-home", dir.resolve("empty/bc-private").toString(),
                    "tsk-file", tsk.toString()));

            assertThat(dir.resolve("out/lib-1.0.jar.asc")).exists();
        }

        @Test
        void twoListedKeysOutsideCertDWriteOneFileWithTwoBlocks() throws IOException {
            String fp1 = generate();
            String fp2 = generate();
            Path certs = moveCertDAside();

            signWithBoth(fp1, fp2, List.of(fp1, fp2));

            List<Credential> listed = List.of(KeyCredential.openPgp(fp1), KeyCredential.openPgp(fp2));
            assertThat(provenByEachBlock(certs)).filteredOn(listed::contains)
                    .containsExactlyInAnyOrderElementsOf(listed);
        }

        @Test
        void aSecondKeyTheSignerDoesNotPinFailsAndWritesNothing() throws IOException {
            String fp1 = generate();
            String fp2 = generate();
            moveCertDAside();

            assertThatThrownBy(() -> signWithBoth(fp1, fp2, List.of(fp1)))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining(fp2);
            try (Stream<Path> written = Files.list(dir.resolve("out"))) {
                assertThat(written).isEmpty();
            }
        }

        /**
         * Signs through {@link Sigmund#signer()} with a bc runner listing both keys, under a
         * signer pinning the given keys.
         */
        private void signWithBoth(String fp1, String fp2, List<String> pinned) throws IOException {
            Path artifact = Files.writeString(dir.resolve("lib-1.0.jar"), "artifact");
            Path out = Files.createDirectories(dir.resolve("out"));
            SigmundConfig config = SigmundConfigParser.parse("<test>", new StringReader("""
                    signers:
                      alice:
                        pgp4: [%s]
                    signing:
                      signer: alice
                      toolchain: [bc]
                    verification:
                      toolchain: [bc]
                      resolve-signers: false
                    """.formatted(String.join(", ", pinned))));
            BcRunner runner = new BcRunner(store(), List.of(fp1, fp2), null, null, null, null,
                    BcRunner.DEFAULT_CIPHER_SUITE);
            try (Sigmund sigmund = Sigmund.builder().config(config).addTool(runner).build()) {
                sigmund.signer().sign(artifact, out);
            }
        }

        /**
         * Moves the certificates out of the signing store, so that bc signs from its secret keys
         * alone, and returns where they went.
         */
        private Path moveCertDAside() throws IOException {
            return Files.move(dir.resolve("cert-d"), dir.resolve("verify-cert-d"));
        }

        /**
         * Verifies every block of the written {@code .asc} against the given certificates and
         * returns what the blocks prove, block by block: bc signs with a subkey, so each block
         * proves its subkey and its primary key.
         */
        private List<Credential> provenByEachBlock(Path certD) throws IOException {
            Path artifact = dir.resolve("lib-1.0.jar");
            BcRunner verifier = new BcRunner(new BcKeyStore(null, certD, dir.resolve("verify-bc-private")),
                    null, null);
            List<Claim> claims = new OpenPgpSignatureFormat()
                    .parse(Evidence.read(dir.resolve("out/lib-1.0.jar.asc"), Evidence.SOURCE_SIDECAR));
            List<Credential> proven = new ArrayList<>();
            for (Claim claim : claims) {
                VerifyResult result = verifier.verify(artifact, claim);
                assertThat(result.isVerified()).as("block verifies").isTrue();
                proven.addAll(verifier.extractCredentials(result));
            }
            return proven;
        }

        private Path exportSecretKey(String fp) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
                store().findSecretKey(fp).encode(armored);
            }
            return Files.write(dir.resolve("key.tsk"), out.toByteArray());
        }

        private String generate() {
            return new BcRunner(store(), null, null).generateKey("Alice <alice@example.com>",
                    "ed25519", null);
        }

        private BcKeyStore store() {
            return new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc-private"));
        }

        private Map<String, String> settings(String fp) {
            return Map.of(
                    "gnupg-home", dir.resolve("gnupg").toString(),
                    "cert-d-home", dir.resolve("cert-d").toString(),
                    "bc-private-home", dir.resolve("bc-private").toString(),
                    "signing-fingerprint", fp);
        }
    }

    @Nested
    @DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
    class Gpg {

        @Test
        void aPinnedKeyWritesTheSignature() throws Exception {
            String fp = generate();

            sign("gpg", fp, Map.of("home", home().toString()));

            assertThat(dir.resolve("out/lib-1.0.jar.asc")).exists();
        }

        @Test
        void anotherKeyFailsNamingBothAndWritesNothing() throws Exception {
            String fp = generate();

            assertMismatch("gpg", fp, Map.of("home", home().toString()));
        }

        private Path home() {
            return dir.resolve("gpg-home");
        }

        private String generate() throws IOException {
            return GpgTestKeys.generate(home(), "Alice <alice@example.com>", "ed25519");
        }

    }

    @Nested
    @DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
    class Sq {

        @Test
        void aPinnedKeyWritesTheSignature() throws IOException {
            String fp = generate();

            sign("sq", fp, settings(fp));

            assertThat(dir.resolve("out/lib-1.0.jar.asc")).exists();
        }

        @Test
        void anotherKeyFailsNamingBothAndWritesNothing() throws IOException {
            String fp = generate();

            assertMismatch("sq", fp, settings(fp));
        }

        private String generate() {
            return new SqRunner(dir.resolve("sq-home"))
                    .generateKey("Alice <alice@example.com>", "cv25519", "rfc9580");
        }

        private Map<String, String> settings(String fp) {
            return Map.of("home", dir.resolve("sq-home").toString(), "signing-fingerprint", fp);
        }
    }

    private void assertMismatch(String tool, String fp, Map<String, String> settings)
            throws IOException {
        assertThatThrownBy(() -> sign(tool, OTHER_FP, settings))
                .isInstanceOf(SigmundException.class)
                .hasMessageContaining("Signature by " + tool)
                .hasMessageContaining("signer 'alice'")
                .hasMessageContaining(fp)
                .hasMessageContaining(OTHER_FP);
        try (Stream<Path> written = Files.list(dir.resolve("out"))) {
            assertThat(written).isEmpty();
        }
    }

    private static String keyType(String fingerprint) {
        return fingerprint.length() == 64 ? Credential.TYPE_PGP6 : Credential.TYPE_PGP4;
    }

    /**
     * Signs an artifact into {@code out} with one tool, under a signer pinning the given key.
     */
    private void sign(String tool, String pinned, Map<String, String> settings)
            throws IOException {
        Path artifact = Files.writeString(dir.resolve("lib-1.0.jar"), "artifact");
        Path out = Files.createDirectories(dir.resolve("out"));
        SigmundConfig config = SigmundConfigParser.parse("<test>", new StringReader("""
                signers:
                  alice:
                    %s: "%s"
                signing:
                  signer: alice
                  toolchain: [%s]
                verification:
                  toolchain: [%s]
                  resolve-signers: false
                """.formatted(keyType(pinned), pinned, tool, tool)));
        try (Sigmund sigmund = Sigmund.builder().config(config)
                .addSigningTool(tool, settings).build()) {
            sigmund.signer().sign(artifact, out);
        }
    }
}
