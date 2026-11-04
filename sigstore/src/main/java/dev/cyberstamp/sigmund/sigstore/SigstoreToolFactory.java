package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.IssuerKind;
import dev.cyberstamp.sigmund.core.SignatureTool;
import dev.cyberstamp.sigmund.core.SignatureToolFactory;
import dev.cyberstamp.sigmund.core.SignerIdentity;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import dev.cyberstamp.sigmund.core.ToolSetting;
import dev.cyberstamp.sigmund.core.TrustRootRef;
import dev.sigstore.KeylessSigner;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.oidc.client.GithubActionsOidcClient;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.OidcTokenMatcher;
import dev.sigstore.oidc.client.TokenStringOidcClient;
import dev.sigstore.strings.StringMatcher;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Factory for creating {@link SigstoreTool} instances.
 * <p>
 * Discovered via {@link java.util.ServiceLoader} when {@code sigmund-sigstore}
 * is on the classpath. Supports three settings:
 * <ul>
 * <li>{@code staging} (boolean, default false) — use {@code sigstage.dev}
 * instead of production {@code sigstore.dev}</li>
 * <li>{@code trusted-root} (path) — custom trusted root JSON file for
 * air-gapped environments</li>
 * <li>{@code interactive} (boolean, default false) — enable browser-based
 * OIDC flow for desktop signing</li>
 * </ul>
 *
 * @see SigstoreTool
 * @see SignatureToolFactory
 */
public class SigstoreToolFactory implements SignatureToolFactory {

    private static final String TOOL_NAME = "sigstore";

    /**
     * Accepts any token subject. Built directly rather than with {@link StringMatcher#regex}, whose
     * syntax exception is checked although {@code .*} cannot fail to compile.
     */
    private static final StringMatcher ANY_SUBJECT = new StringMatcher() {
        @Override
        public boolean test(String subject) {
            return true;
        }

        @Override
        public String toString() {
            return "'Any subject'";
        }
    };

    private final SigstoreSignatureFormat format = new SigstoreSignatureFormat();

    @Override
    public String toolName() {
        return TOOL_NAME;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_SIGSTORE);
    }

    @Override
    public Set<String> acceptedSettings() {
        return ToolSetting.keysOf(Setting.values());
    }

    /**
     * Creates a signing-capable {@link SigstoreTool}.
     * <p>
     * Each {@link IdentityCredential} of {@code expected} whose issuer is an OIDC issuer becomes an
     * {@code allowedOidcIdentities} matcher: on its issuer and exact subject when the entry names a
     * subject, on its issuer alone otherwise. A token none of them accepts is refused before Fulcio
     * is asked for a certificate; every other attribute of an entry is checked on the issued
     * certificate by the check after signing. Entries of an OpenPGP directory contribute nothing.
     * When {@code expected} is {@code null} or has no OIDC entry, any ambient OIDC identity is
     * accepted.
     * <p>
     * When {@code interactive} is {@code true}, the browser-based OIDC flow
     * is enabled as a fallback after ambient providers.
     *
     * @param settings tool settings from the {@code tools.sigstore} config section
     * @param expected the asserted signer, every identity entry naming its issuer, or {@code null}
     * @return a signing-capable Sigstore tool
     * @throws ToolExecutionException if the signer cannot be constructed
     */
    @Override
    public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
        boolean staging = Setting.STAGING.isTrue(settings);
        boolean interactive = Setting.INTERACTIVE.isTrue(settings);
        try {
            KeylessSigner.Builder signerBuilder = staging
                    ? KeylessSigner.builder().sigstoreStagingDefaults()
                    : KeylessSigner.builder().sigstorePublicDefaults();

            if (!interactive) {
                signerBuilder.forceCredentialProviders(OidcClients.of(
                        TokenStringOidcClient.from(new EnvTokenProvider()),
                        GithubActionsOidcClient.builder().build()));
            }

            List<IdentityCredential> allowed = oidcIdentities(expected);
            if (!allowed.isEmpty()) {
                signerBuilder.allowedOidcIdentities(allowed.stream().map(SigstoreToolFactory::matcherFor).toList());
            }
            String sigstoreSubject = firstSubject(allowed);

            KeylessSigner signer = signerBuilder.build();
            KeylessVerifier verifier = buildVerifier(settings, staging);
            return new SigstoreTool(format, signer, verifier, sigstoreSubject, trustRootRef(settings, staging), allowed);
        } catch (Exception e) {
            throw new ToolExecutionException(
                    "Failed to create Sigstore signing tool: " + e.getMessage(), e);
        }
    }

    private static List<IdentityCredential> oidcIdentities(SignerIdentity expected) {
        if (expected == null) {
            return List.of();
        }
        return expected.credentials().stream()
                .filter(IdentityCredential.class::isInstance)
                .map(IdentityCredential.class::cast)
                .filter(identity -> identity.issuer() != null
                        && IssuerKind.of(identity.issuer()) == IssuerKind.OIDC)
                .toList();
    }

    private static String firstSubject(List<IdentityCredential> identities) {
        return identities.stream()
                .map(identity -> identity.attribute(IdentityCredential.SUBJECT))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    /**
     * Builds the token matcher for one OIDC identity entry: its issuer, and its exact subject
     * when the entry names one, any subject otherwise.
     *
     * @param identity an identity entry naming an OIDC issuer
     * @return the matcher a token must satisfy to be accepted for this entry
     */
    static OidcTokenMatcher matcherFor(IdentityCredential identity) {
        String subject = identity.attribute(IdentityCredential.SUBJECT);
        return OidcTokenMatcher.of(
                subject == null ? ANY_SUBJECT : StringMatcher.string(subject),
                StringMatcher.string(identity.issuer()));
    }

    /**
     * Creates a verify-only {@link SigstoreTool}.
     *
     * @param settings tool settings from the {@code tools.sigstore} config section
     * @return a verify-only Sigstore tool
     * @throws ToolExecutionException if the verifier cannot be constructed
     */
    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        boolean staging = Setting.STAGING.isTrue(settings);
        try {
            KeylessVerifier verifier = buildVerifier(settings, staging);
            return new SigstoreTool(format, null, verifier, null,
                    trustRootRef(settings, staging));
        } catch (Exception e) {
            throw new ToolExecutionException(
                    "Failed to create Sigstore verification tool: " + e.getMessage(), e);
        }
    }

    /**
     * Names the trust root {@link #buildVerifier} will use, so results record which
     * certificates were acceptable rather than only that verification was local.
     *
     * @param settings tool settings from the {@code tools.sigstore} config section
     * @param staging whether the staging deployment was selected
     * @return the trust root reference
     */
    private static TrustRootRef trustRootRef(Map<String, String> settings, boolean staging) {
        String trustedRoot = Setting.TRUSTED_ROOT.from(settings);
        if (trustedRoot != null && !trustedRoot.isBlank()) {
            return TrustRootRef.sigstore(trustedRoot);
        }
        return TrustRootRef.sigstore(staging ? "staging" : "public-good");
    }

    private KeylessVerifier buildVerifier(Map<String, String> settings, boolean staging)
            throws Exception {
        String trustedRoot = Setting.TRUSTED_ROOT.from(settings);
        if (trustedRoot != null && !trustedRoot.isBlank()) {
            return KeylessVerifier.builder()
                    .trustedRootProvider(TrustedRootProvider.from(Setting.TRUSTED_ROOT.pathFrom(settings)))
                    .build();
        }
        return staging
                ? KeylessVerifier.builder().sigstoreStagingDefaults().build()
                : KeylessVerifier.builder().sigstorePublicDefaults().build();
    }

    /**
     * Reads an OIDC token from the {@code SIGSTORE_JAVA_ID_TOKEN} environment variable.
     * Mirrors sigstore-java's package-private {@code EnvTokenProvider}.
     */
    static final class EnvTokenProvider implements TokenStringOidcClient.TokenStringProvider {
        private static final String ENV_VAR = "SIGSTORE_JAVA_ID_TOKEN";

        @Override
        public boolean isEnabled(Map<String, String> env) {
            return env.containsKey(ENV_VAR);
        }

        @Override
        public String getTokenString(Map<String, String> env) {
            String token = env.get(ENV_VAR);
            if (token == null) {
                throw new IllegalStateException(ENV_VAR + " was not set");
            }
            return token;
        }
    }

    /** The settings {@code tools.sigstore} accepts, each read only through its constant. */
    private enum Setting implements ToolSetting {
        /** {@code staging}. */
        STAGING("staging"),
        /** {@code trusted-root}. */
        TRUSTED_ROOT("trusted-root"),
        /** {@code interactive}. */
        INTERACTIVE("interactive");

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
