package dev.cyberstamp.sigmund.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * Runs {@code signer-info} against a {@code bc} tool whose named key is absent from its store:
 * {@code bc} reports the key with the type taken from the fingerprint, so the plan is built
 * without any external tool.
 */
class SignerInfoCommandTest {

    private static final String FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567";

    @TempDir
    Path dir;

    @Test
    void aProfileRequestingAMissingTypePrintsTheKeysThenTheProblemAndFails() throws IOException {
        Run run = run("--profile", "hybrid");

        assertEquals(1, run.exitCode());
        List<String> lines = run.out().lines().toList();
        int profile = indexOfLine(lines, "Profile: hybrid", run);
        int key = indexOfLine(lines, "bc: pgp4 " + FINGERPRINT, run);
        int problem = indexOfLine(lines, "Problem: no signing key for requested credential type pgp6", run);
        assertTrue(profile < key && key < problem, run.out());
    }

    @Test
    void withoutAProfileThereIsNoProblemAndTheExitCodeIsZero() throws IOException {
        Run run = run();

        assertEquals(0, run.exitCode(), run.out() + run.err());
        assertTrue(run.out().contains("bc: pgp4 " + FINGERPRINT), run.out());
        assertFalse(run.out().contains("Problem:"), run.out());
    }

    /**
     * Returns the index of the first line containing {@code text}, failing when no line does.
     */
    private static int indexOfLine(List<String> lines, String text, Run run) {
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).contains(text)) {
                return i;
            }
        }
        return fail("no line contains '" + text + "':\n" + run.out());
    }

    private Run run(String... args) throws IOException {
        Path home = Files.createDirectories(dir.resolve("home"));
        Path config = dir.resolve("sigmund.yaml");
        Files.writeString(config, """
                signing:
                  toolchain: [bc]
                  profiles:
                    hybrid: [pgp4, pgp6]
                tools:
                  bc:
                    signing-fingerprint: %s
                    gnupg-home: %s
                    cert-d-home: %s
                    bc-private-home: %s
                """.formatted(FINGERPRINT, home, home, home));

        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        try {
            String[] all = new String[args.length + 2];
            all[0] = "--config";
            all[1] = config.toString();
            System.arraycopy(args, 0, all, 2, args.length);
            int exit = new CommandLine(new SignerInfoCommand()).execute(all);
            return new Run(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    private record Run(int exitCode, String out, String err) {
    }
}
