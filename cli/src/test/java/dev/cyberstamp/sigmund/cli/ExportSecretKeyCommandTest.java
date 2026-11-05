package dev.cyberstamp.sigmund.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * Exports a key {@code keygen} generated, the way the ephemeral CI setup does: the file it writes
 * signs on a machine with no key store.
 */
class ExportSecretKeyCommandTest {

    private static final Pattern FINGERPRINT = Pattern.compile("Fingerprint: ([0-9A-F]+)");

    @TempDir
    Path dir;

    @Test
    void theKeyIsWrittenArmoredToAFileOnlyItsOwnerCanRead() throws IOException {
        String fingerprint = generate();
        Path file = dir.resolve("ci-key.asc");

        Run run = run(ExportSecretKeyCommand::new, "--fingerprint", fingerprint, "--output", file.toString());

        assertEquals(0, run.exitCode(), run.err());
        assertTrue(Files.readString(file).startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        assertTrue(run.err().contains("holds a secret key"), run.err());
        assertTrue(run.out().isEmpty(), run.out());
    }

    @Test
    void theExportedKeySignsWithoutAKeyStore() throws IOException {
        String fingerprint = generate();
        Path file = dir.resolve("ci-key.asc");
        run(ExportSecretKeyCommand::new, "--fingerprint", fingerprint, "--output", file.toString());
        Path empty = dir.resolve("runner");
        Files.writeString(dir.resolve("sigmund.yaml"), """
                tools:
                  bc:
                    tsk-file: %s
                    gnupg-home: %s
                    cert-d-home: %s
                    bc-private-home: %s
                signing:
                  toolchain: [bc]
                """.formatted(file, empty.resolve("gnupg"), empty.resolve("cert-d"), empty.resolve("bc-private")));
        Path artifact = Files.writeString(dir.resolve("lib-1.0.jar"), "artifact");

        Run run = run(SignCommand::new, "--file", artifact.toString());

        assertEquals(0, run.exitCode(), run.out() + run.err());
        assertTrue(Files.exists(dir.resolve("lib-1.0.jar.asc")));
    }

    @Test
    void anExistingFileIsNotOverwritten() throws IOException {
        String fingerprint = generate();
        Path file = Files.writeString(dir.resolve("ci-key.asc"), "keep me");

        Run run = run(ExportSecretKeyCommand::new, "--fingerprint", fingerprint, "--output", file.toString());

        assertEquals(1, run.exitCode());
        assertEquals("keep me", Files.readString(file));
    }

    @Test
    void theKeyIsNeverPrintedToTheConsole() throws IOException {
        String fingerprint = generate();

        Run run = run(ExportSecretKeyCommand::new, "--fingerprint", fingerprint);

        assertNotEquals(0, run.exitCode());
        assertTrue(!run.out().contains("PRIVATE KEY"), run.out());
    }

    private String generate() throws IOException {
        Path home = dir.resolve("bc");
        Files.writeString(dir.resolve("sigmund.yaml"), """
                tools:
                  bc:
                    gnupg-home: %s
                    cert-d-home: %s
                    bc-private-home: %s
                """.formatted(home.resolve("gnupg"), home.resolve("cert-d"), home.resolve("bc-private")));
        Run run = run(KeygenCommand::new, "--userid", "CI <ci@example.com>");
        Matcher fingerprint = FINGERPRINT.matcher(run.out());
        assertTrue(fingerprint.find(), run.out() + run.err());
        return fingerprint.group(1);
    }

    private Run run(Supplier<Object> command, String... args) {
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        try {
            String[] all = new String[args.length + 2];
            all[0] = "--config";
            all[1] = dir.resolve("sigmund.yaml").toString();
            System.arraycopy(args, 0, all, 2, args.length);
            int exit = new CommandLine(command.get()).execute(all);
            return new Run(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    private record Run(int exitCode, String out, String err) {
    }
}
