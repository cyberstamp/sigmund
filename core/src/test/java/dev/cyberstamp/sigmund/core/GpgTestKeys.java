package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

/**
 * GnuPG homes and keys for tests that run the real {@code gpg}.
 */
final class GpgTestKeys {

    private GpgTestKeys() {
    }

    /**
     * Creates {@code dir}, if needed, as a GnuPG home readable only by its owner, as {@code gpg}
     * requires.
     *
     * @param dir the home directory
     * @return {@code dir}
     */
    static Path home(Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        return dir;
    }

    /**
     * Generates a signing key without a passphrase or expiry in {@code home}, creating the home
     * when it does not exist.
     *
     * @param home the GnuPG home
     * @param userId the key's user ID, unique within {@code home}
     * @param algorithm the {@code --quick-gen-key} algorithm, such as {@code ed25519} or
     *        {@code rsa4096}
     * @return the primary key's fingerprint
     */
    static String generate(Path home, String userId, String algorithm) throws IOException {
        Map<String, String> env = Map.of("GNUPGHOME", home(home).toString());
        CliTool.Result generated = CliTool.run(env, "gpg", "--batch", "--passphrase", "", "--pinentry-mode",
                "loopback", "--quick-gen-key", "--yes", userId, algorithm, "sign", "0");
        assertThat(generated.exitCode()).as(generated.stderr()).isZero();
        CliTool.Result listed = CliTool.run(env, "gpg", "--batch", "--with-colons", "--list-secret-keys", userId);
        return listed.stdout().lines()
                .filter(line -> line.startsWith("fpr:"))
                .map(line -> line.split(":")[9])
                .findFirst()
                .orElseThrow();
    }
}
