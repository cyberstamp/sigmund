package io.github.aloubyansky.sigmund.core;

import java.util.Map;
import java.util.Set;

final class GpgToolFactory implements SignatureToolFactory {

    @Override
    public String toolName() {
        return "gpg";
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_OPENPGP_V4);
    }

    @Override
    public SignatureTool create(Credential credential, Map<String, String> settings) {
        String executable = settings.getOrDefault("executable", "gpg");
        String keyName = settings.get("key-name");
        if (keyName == null && credential instanceof FingerprintCredential fp) {
            keyName = fp.fingerprint();
        }
        return new GpgRunner(executable, keyName, settings.get("home"));
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        String executable = settings.getOrDefault("executable", "gpg");
        return new GpgRunner(executable, null, settings.get("home"));
    }
}
