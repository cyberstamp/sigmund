package dev.cyberstamp.sigmund.resolver;

import org.eclipse.aether.RepositorySystemSession;

/**
 * Configuration keys of the Sigmund Maven Resolver extension, read from the session config properties.
 */
public final class SigmundConfigurationKeys {
    private SigmundConfigurationKeys() {
    }

    public static final String CONFIG_PROPS_PREFIX = "sigmund.resolver.";

    /**
     * Whether artifacts downloaded from remote repositories are verified against the Sigmund trust policy before
     * they reach the local repository.
     *
     * @configurationSource {@link RepositorySystemSession#getConfigProperties()}
     * @configurationType {@link Boolean}
     * @configurationDefaultValue {@link #DEFAULT_VERIFY_ENABLED}
     */
    public static final String CONFIG_PROP_VERIFY_ENABLED = CONFIG_PROPS_PREFIX + "verify.enabled";

    public static final boolean DEFAULT_VERIFY_ENABLED = false;

    /**
     * Whether Sigmund signs artifacts on deploy.
     *
     * @configurationSource {@link RepositorySystemSession#getConfigProperties()}
     * @configurationType {@link Boolean}
     * @configurationDefaultValue {@link #DEFAULT_SIGN_ENABLED}
     */
    public static final String CONFIG_PROP_SIGN_ENABLED = CONFIG_PROPS_PREFIX + "sign.enabled";

    public static final boolean DEFAULT_SIGN_ENABLED = false;

    /**
     * Path of the {@code sigmund.yaml} to use. When unset, the file is {@code sigmund.yaml} in the build's root
     * directory, then the user's {@code ~/.config/sigmund/sigmund.yaml}.
     *
     * @configurationSource {@link RepositorySystemSession#getConfigProperties()}
     * @configurationType {@link String}
     */
    public static final String CONFIG_PROP_CONFIG = CONFIG_PROPS_PREFIX + "config";
}
