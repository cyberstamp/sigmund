package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;

/**
 * Signing shortcuts for tests that drive one tool directly.
 */
final class SigningTests {

    private SigningTests() {
    }

    /**
     * Signs with the one key {@code tool} reports, failing when it reports another number of keys,
     * so that a single-key test cannot sign with the first of several.
     *
     * @param tool the signing tool
     * @param artifact the file to sign
     * @param output where the signature is written
     * @return the tool's result
     */
    static SignResult signWithOnlyKey(SignatureTool tool, Path artifact, Path output) {
        List<SigningInfo> keys = tool.signingInfo();
        assertThat(keys).as("keys of " + tool.name()).hasSize(1);
        return tool.sign(artifact, output, keys.get(0));
    }
}
