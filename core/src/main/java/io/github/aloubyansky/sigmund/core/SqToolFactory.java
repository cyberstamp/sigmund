package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

final class SqToolFactory implements SignatureToolFactory {

    @Override
    public String toolName() {
        return "sq";
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6);
    }

    @Override
    public SignatureTool create(Credential credential, Map<String, String> settings) {
        String executable = settings.getOrDefault("executable", "sq");
        Path home = resolveHome(settings);
        String fingerprint = settings.get("signing-fingerprint");
        if (fingerprint == null && credential instanceof FingerprintCredential fp) {
            fingerprint = fp.fingerprint();
        }
        return new SqRunner(executable, home, fingerprint);
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        String executable = settings.getOrDefault("executable", "sq");
        Path home = resolveHome(settings);
        return new SqRunner(executable, home, null);
    }

    private static Path resolveHome(Map<String, String> settings) {
        String homeSetting = settings.get("home");
        if (homeSetting != null) {
            return Path.of(homeSetting);
        }
        Path defaultHome = SqRunner.defaultHome();
        if (defaultHome == null) {
            throw new SigmundException("Cannot determine Sequoia home directory: user.home is not set");
        }
        return defaultHome;
    }
}
