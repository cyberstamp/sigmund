package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
    class Gpg {

        @Test
        void aPinnedKeyWritesTheSignature() throws Exception {
            assumeTrue(GpgRunner.isToolAvailable(), "gpg is not installed");
            String fp = generate();

            sign("gpg", fp, Map.of("home", home().toString()));

            assertThat(dir.resolve("out/lib-1.0.jar.asc")).exists();
        }

        @Test
        void anotherKeyFailsNamingBothAndWritesNothing() throws Exception {
            assumeTrue(GpgRunner.isToolAvailable(), "gpg is not installed");
            String fp = generate();

            assertMismatch("gpg", fp, Map.of("home", home().toString()));
        }

        private Path home() {
            return dir.resolve("gpg-home");
        }

        private String generate() throws IOException {
            Files.createDirectories(home());
            Files.setPosixFilePermissions(home(), PosixFilePermissions.fromString("rwx------"));
            Map<String, String> env = Map.of("GNUPGHOME", home().toString());
            CliTool.Result generated = CliTool.run(env, "gpg", "--batch", "--passphrase", "",
                    "--pinentry-mode", "loopback", "--quick-gen-key", "--yes",
                    "Alice <alice@example.com>", "ed25519", "sign", "0");
            assertThat(generated.exitCode()).as(generated.stderr()).isZero();
            CliTool.Result listed = CliTool.run(env, "gpg", "--batch", "--with-colons",
                    "--list-secret-keys");
            return listed.stdout().lines()
                    .filter(line -> line.startsWith("fpr:"))
                    .map(line -> line.split(":")[9])
                    .findFirst()
                    .orElseThrow();
        }
    }

    @Nested
    class Sq {

        @Test
        void aPinnedKeyWritesTheSignature() throws IOException {
            assumeTrue(SqRunner.isToolAvailable(), "sq is not installed");
            String fp = generate();

            sign("sq", fp, settings(fp));

            assertThat(dir.resolve("out/lib-1.0.jar.asc")).exists();
        }

        @Test
        void anotherKeyFailsNamingBothAndWritesNothing() throws IOException {
            assumeTrue(SqRunner.isToolAvailable(), "sq is not installed");
            String fp = generate();

            assertMismatch("sq", fp, settings(fp));
        }

        private String generate() {
            return new SqRunner(dir.resolve("sq-home"))
                    .generateKey("Alice <alice@example.com>", "cv25519");
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
