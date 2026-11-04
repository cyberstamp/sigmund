package dev.cyberstamp.sigmund.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * Exports the public certificate of a key {@code keygen} generated into stores under the test's
 * directory — what a user publishes so that others can verify their signatures.
 */
class ExportCertCommandTest {

    private static final Pattern FINGERPRINT = Pattern.compile("Fingerprint: ([0-9A-F]+)");
    private static final String PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

    @TempDir
    Path dir;

    @Test
    void aGeneratedKeysCertificateIsPrinted() throws IOException {
        String fingerprint = generate();

        Run run = run(ExportCertCommand::new, "--fingerprint", fingerprint);

        assertEquals(0, run.exitCode(), run.err());
        assertTrue(run.out().startsWith(PUBLIC_KEY), run.out());
        assertTrue(!run.out().contains("PRIVATE KEY"), run.out());
    }

    @Test
    void theCertificateIsWrittenToTheOutputFile() throws IOException {
        String fingerprint = generate();
        Path file = dir.resolve("alice.asc");

        Run run = run(ExportCertCommand::new, "--fingerprint", fingerprint, "--output", file.toString());

        assertEquals(0, run.exitCode(), run.err());
        assertTrue(Files.readString(file).startsWith(PUBLIC_KEY));
    }

    @Test
    void aKeyBouncyCastleDoesNotHoldIsAnError() throws IOException {
        writeConfig();

        Run run = run(ExportCertCommand::new, "--fingerprint", "0123456789ABCDEF0123456789ABCDEF01234567");

        assertEquals(1, run.exitCode());
        assertTrue(run.err().contains("0123456789ABCDEF0123456789ABCDEF01234567"), run.err());
    }

    private String generate() throws IOException {
        writeConfig();
        Run run = run(KeygenCommand::new, "--userid", "Alice <alice@example.com>");
        Matcher fingerprint = FINGERPRINT.matcher(run.out());
        assertTrue(fingerprint.find(), run.out() + run.err());
        return fingerprint.group(1);
    }

    private void writeConfig() throws IOException {
        Path home = dir.resolve("bc");
        Files.writeString(dir.resolve("sigmund.yaml"), """
                tools:
                  bc:
                    gnupg-home: %s
                    cert-d-home: %s
                    bc-private-home: %s
                """.formatted(home.resolve("gnupg"), home.resolve("cert-d"), home.resolve("bc-private")));
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
