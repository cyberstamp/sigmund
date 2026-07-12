package io.github.aloubyansky.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * Operational settings for key discovery, signer info resolution, and per-tool
 * verification configuration.
 * <p>
 * Separated from {@link TrustPolicy} because these are transport/infrastructure
 * concerns, not trust decisions. A trust policy backed by OPA or a database does
 * not need to know about keyservers or tool-specific settings.
 *
 * <h3>Key fetching behavior</h3>
 * <p>
 * When {@link #fetchSignerInfo()} is {@code true} and a key is missing during verification:
 * <ul>
 * <li>{@code importToKeyring = false} (default) — the key is fetched to a temporary
 * location, used for verification, and discarded. Safe for CI and multi-tool environments.</li>
 * <li>{@code importToKeyring = true} — the key is imported into the tool's keyring
 * (GPG keyring, Sequoia cert store). Convenient for interactive use.</li>
 * </ul>
 * <p>
 * When {@link #keyservers()} is empty, {@code hkps://keys.openpgp.org} is used as the default.
 *
 * @param fetchSignerInfo whether to attempt fetching missing signer info
 * @param importToKeyring whether to persist fetched keys into the tool's keyring
 * @param keyservers keyserver URLs for key discovery (empty = default)
 * @param tools per-tool verification settings, keyed by tool name
 */
public record DiscoveryConfig(
        boolean fetchSignerInfo,
        boolean importToKeyring,
        List<String> keyservers,
        Map<String, Map<String, String>> tools) {

    /**
     * Default discovery configuration: fetch signer info enabled, ephemeral key fetching,
     * tool-default keyservers, no per-tool overrides.
     */
    public static final String DEFAULT_KEYSERVER = "hkps://keys.openpgp.org";

    public static final DiscoveryConfig DEFAULT = new DiscoveryConfig(true, false, List.of(DEFAULT_KEYSERVER), Map.of());

    /**
     * Creates a new discovery configuration with defensive copies.
     */
    public DiscoveryConfig {
        keyservers = keyservers != null && !keyservers.isEmpty() ? List.copyOf(keyservers) : List.of(DEFAULT_KEYSERVER);
        tools = tools != null ? Map.copyOf(tools) : Map.of();
    }
}
