package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link CliTool}.
 */
class CliToolTest {

    /**
     * Verifies that stdout is captured correctly from a simple echo command.
     */
    @Test
    void run_capturesStdout() {
        CliTool.Result result = CliTool.run("echo", "hello");

        assertEquals(0, result.exitCode(), "Exit code should be 0");
        assertEquals("hello", result.stdout().trim(), "Stdout should contain 'hello'");
    }

    /**
     * Verifies that stderr is captured correctly from a command that writes to stderr.
     */
    @Test
    void run_capturesStderr() {
        CliTool.Result result = CliTool.run("sh", "-c", "echo err >&2");

        assertEquals(0, result.exitCode(), "Exit code should be 0");
        assertEquals("err", result.stderr().trim(), "Stderr should contain 'err'");
    }

    /**
     * Verifies that run() does not throw an exception for non-zero exit codes.
     */
    @Test
    void run_nonZeroExit_doesNotThrow() {
        CliTool.Result result = CliTool.run("sh", "-c", "exit 42");

        assertEquals(42, result.exitCode(), "Exit code should be 42");
    }

}
