package dev.cyberstamp.sigmund.sigstore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import dev.cyberstamp.sigmund.core.OpenPgpClaim;
import dev.cyberstamp.sigmund.core.SigstoreClaim;
import dev.cyberstamp.sigmund.core.SigstoreVerifyResult;
import dev.cyberstamp.sigmund.core.VerifyResult;
import dev.sigstore.KeylessVerificationException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SigstoreToolTest {

    private final SigstoreSignatureFormat format = new SigstoreSignatureFormat();

    /**
     * Creates a tool with no signer and no verifier — suitable only for testing
     * metadata methods and {@code extractCredentials()}, not {@code sign()} or {@code verify()}.
     */
    private SigstoreTool metadataOnlyTool() {
        return new SigstoreTool(format, null, null, null);
    }

    @Nested
    class Properties {
        @Test
        void name() {
            assertThat(metadataOnlyTool().name()).isEqualTo("sigstore");
        }

        @Test
        void isAlwaysAvailable() {
            assertThat(metadataOnlyTool().isAvailable()).isTrue();
        }

        @Test
        void cannotSignWithoutSigner() {
            assertThat(metadataOnlyTool().canSign()).isFalse();
        }

        @Test
        void signatureFormat() {
            assertThat(metadataOnlyTool().signatureFormat()).isSameAs(format);
        }

        @Test
        void supportedCredentialTypes() {
            assertThat(metadataOnlyTool().supportedCredentialTypes()).isEqualTo(Set.of("sigstore"));
        }

        @Test
        void signingInfoEmptyWhenVerifyOnly() {
            assertThat(metadataOnlyTool().signingInfo().isEmpty()).isTrue();
        }
    }

    @Nested
    class SigningInfoType {

        @Test
        void aSigningToolReportsTheSigstoreType() {
            try (var tool = (SigstoreTool) new SigstoreToolFactory().createSigning(Map.of("staging", "true"), null)) {
                assertThat(tool.signingInfo()).hasSize(1);
                assertThat(tool.signingInfo().get(0).credentialType()).isEqualTo("sigstore");
            }
        }
    }

    @Nested
    class CanVerify {
        @Test
        void acceptsSigstoreClaim() {
            assertThat(metadataOnlyTool().canVerify(
                    new SigstoreClaim("{}", null))).isTrue();
        }

        @Test
        void rejectsOpenPgpClaim() {
            assertThat(metadataOnlyTool().canVerify(
                    new OpenPgpClaim("block", 4, null, 0, null))).isFalse();
        }
    }

    @Nested
    class ExtractCredentials {
        @Test
        void aVerifiedResultProvesItsIdentity() {
            var identity = new IdentityCredential("https://accounts.google.com", Map.of(
                    IdentityCredential.SUBJECT, "alice@example.com",
                    IdentityCredential.EMAIL, "alice@example.com"));
            var result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, "alice@example.com", "EC",
                    identity, "12345", GeneralName.rfc822Name);

            assertThat(metadataOnlyTool().extractCredentials(result)).containsExactly(identity);
        }

        @Test
        void failedVerificationProducesNoCredentials() {
            var result = new SigstoreVerifyResult(ClaimOutcome.FAILED, null, null, null, null, null, -1);
            assertThat(metadataOnlyTool().extractCredentials(result)).isEmpty();
        }

        @Test
        void aCertificateWithoutIssuerProducesNoCredentials() {
            var result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, "alice@example.com", "EC",
                    null, "12345", GeneralName.rfc822Name);

            assertThat(metadataOnlyTool().extractCredentials(result)).isEmpty();
        }
    }

    @Nested
    class CertificateIdentity {
        static final String ACTIONS = "https://token.actions.githubusercontent.com";

        @Test
        void workflowCertificateCarriesIssuerSubjectAndExtensions() throws Exception {
            String workflow = "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0";
            X509Certificate cert = FulcioCertificates.create(ACTIONS,
                    new GeneralName(GeneralName.uniformResourceIdentifier, workflow),
                    Map.of("12", "https://github.com/org/repo",
                            "14", "refs/tags/v1.0",
                            "23", "release"));

            IdentityCredential identity = SigstoreTool.identityOf(cert);

            assertThat(identity.issuer()).isEqualTo(ACTIONS);
            assertThat(identity.attributes())
                    .containsEntry(IdentityCredential.SUBJECT, workflow)
                    .containsEntry("source-repository-uri", "https://github.com/org/repo")
                    .containsEntry("source-repository-ref", "refs/tags/v1.0")
                    .containsEntry("deployment-environment", "release")
                    .doesNotContainKey(IdentityCredential.EMAIL);
        }

        @Test
        void emailSubjectIsAlsoAnEmailAttribute() throws Exception {
            X509Certificate cert = FulcioCertificates.create("https://accounts.google.com",
                    new GeneralName(GeneralName.rfc822Name, "Alice@Example.com"), Map.of());

            IdentityCredential identity = SigstoreTool.identityOf(cert);

            assertThat(identity.attribute(IdentityCredential.SUBJECT)).isEqualTo("Alice@Example.com");
            assertThat(identity.attribute(IdentityCredential.EMAIL)).isEqualTo("alice@example.com");
        }

        @Test
        void deprecatedGithubExtensionsAreIgnored() throws Exception {
            X509Certificate cert = FulcioCertificates.create(ACTIONS,
                    new GeneralName(GeneralName.uniformResourceIdentifier, "https://github.com/org/repo"),
                    Map.of("2", "push"));

            assertThat(SigstoreTool.identityOf(cert).attributes())
                    .containsOnlyKeys(IdentityCredential.SUBJECT);
        }

        @Test
        void certificateWithoutIssuerProvesNothing() throws Exception {
            X509Certificate cert = FulcioCertificates.create(null,
                    new GeneralName(GeneralName.rfc822Name, "alice@example.com"), Map.of());

            assertThat(SigstoreTool.identityOf(cert)).isNull();
        }
    }

    @Nested
    class Lifecycle {
        @Test
        void closeIsNoOpForVerifyOnly() {
            assertThatCode(() -> metadataOnlyTool().close()).doesNotThrowAnyException();
        }

        @Test
        void signThrowsWithoutSigner() {
            assertThatThrownBy(() -> metadataOnlyTool().sign(null, null, null))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void verifyThrowsWithoutVerifier() {
            assertThatThrownBy(() -> metadataOnlyTool().verify(null, new SigstoreClaim("{}", null)))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    class FailureMapping {

        @Test
        void unparseableBundleIsIndeterminateNotFailed() {
            VerifyResult result = SigstoreTool.evidenceMalformed();
            assertThat(result.isFailed()).isFalse();
            assertThat(result.isIndeterminate(IndeterminateReason.EVIDENCE_MALFORMED)).isTrue();
        }

        @Test
        void infrastructureFailureIsIndeterminateRatherThanThrown() {
            KeylessVerificationException networkFailure = new KeylessVerificationException(
                    "could not reach the trust root", new IOException("connection refused"));

            VerifyResult result = metadataOnlyTool().handleVerificationException(networkFailure);

            assertThat(result.isIndeterminate(IndeterminateReason.TRUST_ROOT_UNAVAILABLE)).isTrue();
        }

        @Test
        void badSignatureRemainsFailed() {
            KeylessVerificationException badSignature = new KeylessVerificationException("signature did not verify");

            VerifyResult result = metadataOnlyTool().handleVerificationException(badSignature);

            assertThat(result.isFailed()).isTrue();
            assertThat(result.reason()).isNull();
        }
    }
}
