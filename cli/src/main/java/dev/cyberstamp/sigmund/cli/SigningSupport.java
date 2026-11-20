package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.Signer;

/**
 * Shared logic for CLI commands that build a signing-capable Sigmund instance.
 */
final class SigningSupport {

    private SigningSupport() {
    }

    static Sigmund buildSigningSigmund(SigmundConfig config, SqHomeMixin sqHomeMixin) {
        Sigmund.Builder builder = Sigmund.builder().config(config);
        if (sqHomeMixin != null) {
            builder.toolsConfig(sqHomeMixin.applyTo(config.toolsConfig()));
        }
        return builder
                .addSigningTools(name -> System.err.println("Note: signing tool '" + name + "' not available, skipping"))
                .build();
    }

    /**
     * Creates the signer for a named profile, or the default signer when none is named: the
     * profile's credential types, else {@code signing.credential-types}, choose the keys that sign.
     *
     * @param sigmund the configured instance
     * @param profile one of {@code signing.profiles}, or {@code null}
     * @return the signer
     */
    static Signer signer(Sigmund sigmund, String profile) {
        return profile != null ? sigmund.signer(profile) : sigmund.signer();
    }
}
