package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;
import java.util.Set;

final class GpgToolFactory implements SignatureToolFactory {

    /** The tool's name under {@code tools} and in toolchains. */
    static final String NAME = "gpg";

    private static final String DEFAULT_PASSPHRASE_ENV = "SIGMUND_GPG_PASSPHRASE";

    /**
     * Reads the GnuPG home gpg's settings name.
     *
     * @param settings gpg's settings
     * @return {@code tools.gpg.home}, or {@code null} when not set
     */
    static String home(Map<String, String> settings) {
        return Setting.HOME.from(settings);
    }

    @Override
    public String toolName() {
        return NAME;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_PGP4);
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
        signingFingerprints(settings);
    }

    private static List<String> signingFingerprints(Map<String, String> settings) {
        List<String> fingerprints = SigningFingerprint.allFrom(NAME, Setting.SIGNING_FINGERPRINT, settings);
        for (String fingerprint : fingerprints) {
            if (!Credential.TYPE_PGP4.equals(KeyCredential.openPgp(fingerprint).type())) {
                throw new PolicyConfigException("tools." + NAME + "." + Setting.SIGNING_FINGERPRINT.key() + ": '"
                        + fingerprint + "' is a v6 fingerprint; gpg signs with v4 keys only");
            }
        }
        return fingerprints;
    }

    @Override
    public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
        String executable = Setting.EXECUTABLE.from(settings, "gpg");
        List<String> fingerprints = signingFingerprints(settings);
        String passphrase = resolvePassphrase(settings);
        return new GpgRunner(executable, fingerprints,
                Setting.HOME.from(settings), passphrase, false, false, List.of());
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        String executable = Setting.EXECUTABLE.from(settings, "gpg");
        boolean resolveSigners = FetchSetting.RESOLVE_SIGNERS.isTrue(settings);
        boolean importToKeyring = FetchSetting.IMPORT_TO_KEYRING.isTrue(settings);
        List<String> keyservers = VerificationConfig.parseKeyserversSetting(FetchSetting.KEYSERVERS.from(settings));
        return new GpgRunner(executable, List.of(), Setting.HOME.from(settings),
                null, false, resolveSigners, importToKeyring, keyservers);
    }

    private static String resolvePassphrase(Map<String, String> settings) {
        String configuredEnv = Setting.PASSPHRASE_ENV.from(settings);
        String envVar = configuredEnv != null ? configuredEnv : DEFAULT_PASSPHRASE_ENV;
        String value = System.getenv(envVar);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        if (configuredEnv != null) {
            throw new SigmundException(
                    "Environment variable " + configuredEnv + " is not set");
        }
        return null;
    }

    /** The settings {@code tools.gpg} accepts, each read only through its constant. */
    private enum Setting implements ToolSetting {
        /** {@code executable}. */
        EXECUTABLE("executable"),
        /** {@code signing-fingerprint}, one full fingerprint or a list of them. */
        SIGNING_FINGERPRINT("signing-fingerprint") {
            @Override
            public boolean takesList() {
                return true;
            }
        },
        /** {@code home}. */
        HOME("home"),
        /** {@code passphrase-env}. */
        PASSPHRASE_ENV("passphrase-env");

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
