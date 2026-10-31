package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class SqToolFactory implements SignatureToolFactory {

    @Override
    public String toolName() {
        return "sq";
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

    /**
     * {@inheritDoc}
     *
     * <p>
     * Signs with the keys {@code signing-fingerprint} names, else with the key sq's own
     * configuration names under {@code sign.signer-self}; without either the tool cannot sign.
     */
    @Override
    public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
        String executable = Setting.EXECUTABLE.from(settings, "sq");
        Path home = resolveHome(settings);
        List<String> fingerprints = SigningFingerprint.allFrom(toolName(), Setting.SIGNING_FINGERPRINT, settings);
        if (fingerprints.isEmpty()) {
            String signerSelf = SqRunner.querySignerSelf(executable, SqRunner.envFor(home));
            fingerprints = signerSelf == null ? List.of() : List.of(signerSelf);
        }
        return new SqRunner(executable, home, fingerprints);
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        String executable = Setting.EXECUTABLE.from(settings, "sq");
        Path home = resolveHome(settings);
        return new SqRunner(executable, home, List.of());
    }

    private static Path resolveHome(Map<String, String> settings) {
        String homeSetting = Setting.HOME.from(settings);
        return homeSetting != null ? Path.of(homeSetting) : null;
    }

    /** The settings {@code tools.sq} accepts, each read only through its constant. */
    private enum Setting implements ToolSetting {
        /** {@code home}. */
        HOME("home"),
        /** {@code executable}. */
        EXECUTABLE("executable"),
        /** {@code signing-fingerprint}, one full fingerprint or a list of them. */
        SIGNING_FINGERPRINT("signing-fingerprint") {
            @Override
            public boolean takesList() {
                return true;
            }
        };

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
