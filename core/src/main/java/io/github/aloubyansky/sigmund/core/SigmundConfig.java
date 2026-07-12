package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.Map;

/**
 * Unified configuration parsed from a single YAML file ({@code sigmund.yaml}).
 * <p>
 * Produces separate typed objects for different consumers while keeping the
 * user's configuration in one place. {@code signers} is a top-level shared
 * registry of known identities — referenced by both {@link TrustPolicy}
 * (via trust mappings) and {@link SigningConfig} (via signer name).
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * SigmundConfig config = SigmundConfig.parse(Path.of("sigmund.yaml"));
 * TrustPolicy policy = config.trustPolicy();
 * SigningConfig signing = config.signingConfig();
 * DiscoveryConfig discovery = config.discoveryConfig();
 * }</pre>
 *
 * @param version the schema version (currently 1)
 * @param signers shared identity registry keyed by signer id
 * @param trustPolicy the trust policy parsed from trust/unsigned/policy sections
 * @param signingConfig the signing configuration parsed from the signing section
 * @param discoveryConfig the discovery configuration parsed from the discovery section
 * @see SigmundConfigParser
 */
public record SigmundConfig(
        int version,
        Map<String, SignerIdentity> signers,
        TrustPolicy trustPolicy,
        SigningConfig signingConfig,
        DiscoveryConfig discoveryConfig) {

    /**
     * Creates a config with defensive copies.
     */
    public SigmundConfig {
        signers = signers != null ? Map.copyOf(signers) : Map.of();
        if (trustPolicy == null) {
            trustPolicy = DefaultTrustPolicy.EMPTY;
        }
        if (signingConfig == null) {
            signingConfig = SigningConfig.DEFAULT;
        }
        if (discoveryConfig == null) {
            discoveryConfig = DiscoveryConfig.DEFAULT;
        }
    }

    /**
     * Parses a {@code sigmund.yaml} configuration file.
     *
     * @param file the path to the YAML file
     * @return the parsed configuration
     * @throws PolicyConfigException if the file cannot be read or contains invalid configuration
     */
    public static SigmundConfig parse(Path file) {
        return SigmundConfigParser.parse(file);
    }
}
