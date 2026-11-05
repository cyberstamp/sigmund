package dev.cyberstamp.sigmund.core;

/**
 * {@link Sigmund} shortcuts for tests.
 */
final class SigmundTests {

    private SigmundTests() {
    }

    /**
     * Builds and closes an instance, for a test expecting the build to fail: should it succeed
     * instead, the instance and the tools it opened are still closed.
     *
     * @param builder the builder
     */
    static void buildAndClose(Sigmund.Builder builder) {
        try (Sigmund sigmund = builder.build()) {
            // closed even if the build was expected to fail and did not
        }
    }
}
