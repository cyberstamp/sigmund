package dev.cyberstamp.sigmund.core;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Factory for constructing {@link BcRunner} instances from configuration.
 */
final class BcToolFactory implements SignatureToolFactory {

    /** The tool's name under {@code tools} and in toolchains. */
    static final String NAME = "bc";

    @Override
    public String toolName() {
        return NAME;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_PGP4, Credential.TYPE_PGP6);
    }

    @Override
    public Set<String> acceptedSettings() {
        return ToolSetting.keysOf(Setting.values());
    }

    @Override
    public Set<String> listSettings() {
        return ToolSetting.listKeysOf(Setting.values());
    }

    @Override
    public void checkSettingValues(Map<String, String> settings) {
        SigningFingerprint.allFrom(toolName(), Setting.SIGNING_FINGERPRINT, settings);
    }

    private static final String DEFAULT_PASSPHRASE_ENV = "SIGMUND_BC_PASSPHRASE";
    private static final String DEFAULT_SIGNING_KEY_ENV = "SIGMUND_BC_SIGNING_KEY";

    @Override
    public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
        return createSigning(settings, expected, null);
    }

    /**
     * Creates a signing-capable tool with an explicit passphrase provider.
     * <p>
     * The explicit provider bypasses settings-based resolution entirely,
     * preserving the {@code char[]}-based passphrase lifecycle. Called by
     * {@link Sigmund.Builder} when a {@link PassphraseProvider} was set
     * via {@link Sigmund.Builder#bcPassphraseProvider}.
     *
     * <h4>Signing key priority</h4>
     * <ol>
     * <li>{@code SIGMUND_BC_SIGNING_KEY} env var (or custom {@code signing-key-env})</li>
     * <li>{@code tsk-file} setting</li>
     * <li>{@code signing-fingerprint} setting</li>
     * </ol>
     * <p>
     * The env var takes precedence so that CI environments can override
     * file-based configuration without modifying {@code sigmund.yaml}.
     */
    SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected,
            PassphraseProvider explicitProvider) {
        List<String> configuredFingerprints = SigningFingerprint.allFrom(toolName(), Setting.SIGNING_FINGERPRINT,
                settings);
        BcKeyStore keyStore = buildKeyStore(settings);
        byte[] tskBytes = resolveSigningKeyBytes(settings);
        Path tskFile = tskBytes == null ? resolveOptionalPath(settings, Setting.TSK_FILE) : null;
        List<String> fingerprints = tskBytes == null && tskFile == null ? configuredFingerprints : List.of();
        PassphraseProvider provider = explicitProvider != null
                ? explicitProvider
                : resolvePassphraseProvider(settings);
        return new BcRunner(keyStore, fingerprints, tskFile, tskBytes, provider,
                null, Setting.CIPHER_SUITE.from(settings, BcRunner.DEFAULT_CIPHER_SUITE));
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        BcKeyStore keyStore = buildKeyStore(settings);
        boolean resolveSigners = FetchSetting.RESOLVE_SIGNERS.isTrue(settings);
        List<String> keyservers = VerificationConfig.parseKeyserversSetting(FetchSetting.KEYSERVERS.from(settings));
        KeyserverFetcher fetcher = resolveSigners && !keyservers.isEmpty()
                ? new KeyserverFetcher(keyStore, keyservers)
                : null;
        return new BcRunner(keyStore, null, null, null, null, fetcher);
    }

    /**
     * Builds a key store from the given settings.
     */
    private static BcKeyStore buildKeyStore(Map<String, String> settings) {
        Path gnupgHome = resolveGnupgHome(settings);
        Path certDHome = resolveCertDHome(settings);
        Path bcPrivateHome = resolveBcPrivateHome(settings);
        return new BcKeyStore(gnupgHome, certDHome, bcPrivateHome,
                FetchSetting.IMPORT_TO_KEYRING.isTrue(settings));
    }

    /**
     * Makes the GnuPG home gpg uses bc's default too, so a keyring placed for gpg is the one bc
     * reads public keys from. bc's cert-d and private key store are not GnuPG's and are left to
     * their own defaults.
     *
     * @param settings bc's settings, mutated: {@code gnupg-home} is added when not set
     * @param gpgHome the home {@code tools.gpg.home} names, or {@code null} when not set
     */
    static void defaultGnupgHome(Map<String, String> settings, String gpgHome) {
        if (gpgHome != null) {
            settings.putIfAbsent(Setting.GNUPG_HOME.key(), gpgHome);
        }
    }

    /**
     * Resolves the GnuPG home directory.
     */
    private static Path resolveGnupgHome(Map<String, String> settings) {
        String home = Setting.GNUPG_HOME.from(settings);
        if (home != null) {
            return Path.of(home);
        }
        String userHome = System.getProperty("user.home");
        return userHome != null ? Path.of(userHome, ".gnupg") : null;
    }

    /**
     * Resolves the shared cert-d directory.
     *
     * <p>
     * Defaults to {@code ~/.local/share/pgp.cert.d}, the location the shared OpenPGP certificate
     * directory specification names and {@code sq} uses as its certificate store, so that
     * certificates one tool stores are visible to the other.
     */
    static Path resolveCertDHome(Map<String, String> settings) {
        String home = Setting.CERT_D_HOME.from(settings);
        if (home != null) {
            return Path.of(home);
        }
        return localShare("cert-d home").resolve("pgp.cert.d");
    }

    /**
     * Resolves the BC private key store directory.
     *
     * <p>
     * Defaults to {@code ~/.local/share/sigmund/bc-private}, outside the cert-d: the cert-d is a
     * public certificate store shared with other tools, and secret keys do not belong in it.
     */
    static Path resolveBcPrivateHome(Map<String, String> settings) {
        String home = Setting.BC_PRIVATE_HOME.from(settings);
        if (home != null) {
            return Path.of(home);
        }
        return localShare("BC private key store").resolve("sigmund").resolve("bc-private");
    }

    private static Path localShare(String purpose) {
        String userHome = System.getProperty("user.home");
        if (userHome == null) {
            throw new SigmundException("Cannot determine " + purpose + ": user.home is not set");
        }
        return Path.of(userHome, ".local", "share");
    }

    /**
     * Resolves an optional file path from settings.
     */
    private static Path resolveOptionalPath(Map<String, String> settings, ToolSetting setting) {
        String value = setting.from(settings);
        return value != null ? Path.of(value) : null;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns {@code true} when the default {@code SIGMUND_BC_SIGNING_KEY} env var
     * is set and non-empty — indicating an ephemeral signing key was injected
     * from the environment, typically a CI secret. When no signing tools are
     * configured in {@code sigmund.yaml}, the builder uses this to make BC the
     * sole signer, preventing other tools (GPG, sq) from co-signing with
     * unintended default keys.
     * <p>
     * A custom env var name configured via {@code signing-key-env} in
     * {@code sigmund.yaml} is not checked here, because that configuration
     * implies BC is already listed as an explicit signing tool — this method
     * is not consulted when signing tools are explicitly configured.
     */
    @Override
    public boolean isDefaultExclusiveSigner() {
        String value = System.getenv(DEFAULT_SIGNING_KEY_ENV);
        return value != null && !value.isEmpty();
    }

    /**
     * Resolves signing key bytes from the environment, using {@link System#getenv}.
     *
     * @see #resolveSigningKeyBytes(Map, Function)
     */
    private static byte[] resolveSigningKeyBytes(Map<String, String> settings) {
        return resolveSigningKeyBytes(settings, System::getenv);
    }

    /**
     * Resolves the raw signing key bytes from an environment variable.
     * <p>
     * Resolution order:
     * <ol>
     * <li>If {@code signing-key-env} is present in settings, use that as the env var name.</li>
     * <li>Otherwise, use the default {@code SIGMUND_BC_SIGNING_KEY}.</li>
     * </ol>
     * <p>
     * If the resolved env var is set and non-empty, its value is returned as UTF-8 bytes.
     * If a custom env var name was configured but the variable is not set (or empty),
     * a {@link SigmundException} is thrown — the user explicitly asked for it. If the
     * default env var is simply absent, {@code null} is returned (no error).
     *
     * @param settings tool-specific settings from the config
     * @param envLookup function mapping env var name to value (or {@code null})
     * @return the key bytes, or {@code null} if the default env var is not set
     * @throws SigmundException if a custom {@code signing-key-env} was configured
     *         but the environment variable is not set or empty
     */
    static byte[] resolveSigningKeyBytes(Map<String, String> settings,
            Function<String, String> envLookup) {
        String configuredEnv = Setting.SIGNING_KEY_ENV.from(settings);
        String envVar = configuredEnv != null ? configuredEnv : DEFAULT_SIGNING_KEY_ENV;
        String envValue = envLookup.apply(envVar);
        if (envValue != null && !envValue.isEmpty()) {
            return envValue.getBytes(StandardCharsets.UTF_8);
        }
        if (configuredEnv != null) {
            throw new SigmundException("Environment variable " + configuredEnv + " is not set");
        }
        return null;
    }

    /**
     * Resolves a passphrase provider from settings.
     * <p>
     * Priority: {@code passphrase-env} setting (env var name, default
     * {@code SIGMUND_BC_PASSPHRASE}), then interactive console prompt if available.
     */
    private static PassphraseProvider resolvePassphraseProvider(Map<String, String> settings) {
        String configuredEnv = Setting.PASSPHRASE_ENV.from(settings);
        String envVar = configuredEnv != null ? configuredEnv : DEFAULT_PASSPHRASE_ENV;
        String envValue = System.getenv(envVar);
        if (envValue != null && !envValue.isEmpty()) {
            return fp -> envValue.toCharArray();
        }
        if (configuredEnv != null) {
            throw new SigmundException(
                    "Environment variable " + configuredEnv + " is not set");
        }
        Console console = System.console();
        if (console != null) {
            Map<String, char[]> cache = new ConcurrentHashMap<>();
            return fp -> {
                char[] cached = cache.computeIfAbsent(fp,
                        k -> console.readPassword("Passphrase for BC key %s: ", k));
                return Arrays.copyOf(cached, cached.length);
            };
        }
        return null;
    }

    /** The settings {@code tools.bc} accepts, each read only through its constant. */
    private enum Setting implements ToolSetting {
        /** {@code gnupg-home}. */
        GNUPG_HOME("gnupg-home"),
        /** {@code cert-d-home}. */
        CERT_D_HOME("cert-d-home"),
        /** {@code bc-private-home}. */
        BC_PRIVATE_HOME("bc-private-home"),
        /** {@code signing-fingerprint}, one full fingerprint or a list of them. */
        SIGNING_FINGERPRINT("signing-fingerprint") {
            @Override
            public boolean takesList() {
                return true;
            }
        },
        /** {@code tsk-file}. */
        TSK_FILE("tsk-file"),
        /** {@code signing-key-env}. */
        SIGNING_KEY_ENV("signing-key-env"),
        /** {@code passphrase-env}. */
        PASSPHRASE_ENV("passphrase-env"),
        /** {@code cipher-suite}. */
        CIPHER_SUITE("cipher-suite");

        private final String key;

        Setting(String key) {
            this.key = key;
        }

        @Override
        public String key() {
            return key;
        }
    }
}
