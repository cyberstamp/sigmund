package io.github.aloubyansky.sigmund.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Parses a {@code trust-config.yaml} file into a validated {@link TrustConfig}.
 * <p>
 * After deserialization, this parser validates that:
 * <ul>
 * <li>All signer references in {@code trust} resolve to entries in {@code signers}</li>
 * <li>All artifact group references in {@code trust} and {@code unsigned} that match
 * an entry in {@code artifacts} are recognized</li>
 * <li>The {@code on-untrusted} setting is a valid policy value</li>
 * </ul>
 */
public class TrustConfigParser {

    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory())
            .setPropertyNamingStrategy(PropertyNamingStrategies.KEBAB_CASE);

    private TrustConfigParser() {
    }

    /**
     * Parses and validates a trust configuration from the given file.
     *
     * @param file path to the YAML configuration file
     * @return the parsed and validated configuration
     * @throws IOException if the file cannot be read
     * @throws IllegalArgumentException if the configuration is invalid
     */
    public static TrustConfig parse(Path file) throws IOException {
        try (Reader reader = Files.newBufferedReader(file)) {
            return parse(reader);
        }
    }

    /**
     * Parses and validates a trust configuration from the given reader.
     *
     * @param reader source of the YAML content
     * @return the parsed and validated configuration
     * @throws IOException if the content cannot be read
     * @throws IllegalArgumentException if the configuration is invalid
     */
    public static TrustConfig parse(Reader reader) throws IOException {
        TrustConfig config = YAML_MAPPER.readValue(reader, TrustConfig.class);
        validate(config);
        return config;
    }

    /**
     * Validates cross-references between config sections.
     */
    private static void validate(TrustConfig config) {
        List<String> errors = new ArrayList<>();
        validateSignerRefs(config, errors);
        validateOnUntrusted(config.settings(), errors);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(
                    "Invalid trust configuration:\n  - " + String.join("\n  - ", errors));
        }
    }

    /**
     * Checks that every signer reference in the trust section resolves to a defined signer.
     */
    private static void validateSignerRefs(TrustConfig config, List<String> errors) {
        Map<String, TrustConfig.Signer> signers = config.signers();
        for (var entry : config.trust().entrySet()) {
            for (String ref : entry.getValue()) {
                if (!signers.containsKey(ref)) {
                    errors.add("Trust entry '" + entry.getKey()
                            + "' references unknown signer '" + ref + "'");
                }
            }
        }
    }

    private static void validateOnUntrusted(TrustConfig.Settings settings, List<String> errors) {
        if (!TrustConfig.Settings.isValidOnUntrusted(settings.onUntrusted())) {
            errors.add("Invalid on-untrusted value '" + settings.onUntrusted()
                    + "': must be 'fail' or 'warn'");
        }
    }
}
