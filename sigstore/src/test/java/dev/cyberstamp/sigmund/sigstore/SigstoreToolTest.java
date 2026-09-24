package dev.cyberstamp.sigmund.sigstore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.EmailCredential;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import dev.cyberstamp.sigmund.core.OpenPgpClaim;
import dev.cyberstamp.sigmund.core.SigstoreClaim;
import dev.cyberstamp.sigmund.core.SigstoreCredential;
import dev.cyberstamp.sigmund.core.SigstoreVerifyResult;
import dev.cyberstamp.sigmund.core.VerifyResult;
import dev.sigstore.KeylessVerificationException;
import java.io.IOException;
import java.util.List;
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
        void emailSubjectProducesBothCredentials() {
            var sc = new SigstoreCredential.Builder()
                    .issuer("https://accounts.google.com")
                    .subject("alice@example.com")
                    .build();
            var result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, "alice@example.com", "EC",
                    sc, "12345", GeneralName.rfc822Name);

            List<Credential> credentials = metadataOnlyTool().extractCredentials(result);

            assertThat(credentials.size()).isEqualTo(2);
            assertThat(credentials.get(0)).isInstanceOf(SigstoreCredential.class);
            assertThat(credentials.get(1)).isInstanceOf(EmailCredential.class);

            SigstoreCredential extracted = (SigstoreCredential) credentials.get(0);
            assertThat(extracted.issuer()).isEqualTo("https://accounts.google.com");
            assertThat(extracted.subject()).isEqualTo("alice@example.com");

            EmailCredential email = (EmailCredential) credentials.get(1);
            assertThat(email.email()).isEqualTo("alice@example.com");
        }

        @Test
        void uriSubjectProducesOnlySigstoreCredential() {
            var sc = new SigstoreCredential.Builder()
                    .issuer("https://token.actions.githubusercontent.com")
                    .subject("https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0")
                    .sourceRepositoryUri("https://github.com/org/repo")
                    .build();
            var result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null,
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0",
                    "EC", sc, "67890",
                    GeneralName.uniformResourceIdentifier);

            List<Credential> credentials = metadataOnlyTool().extractCredentials(result);

            assertThat(credentials.size()).isEqualTo(1);
            assertThat(credentials.get(0)).isInstanceOf(SigstoreCredential.class);
            SigstoreCredential extracted = (SigstoreCredential) credentials.get(0);
            assertThat(extracted.sourceRepositoryUri()).isEqualTo("https://github.com/org/repo");
        }

        @Test
        void failedVerificationProducesNoCredentials() {
            var result = new SigstoreVerifyResult(ClaimOutcome.FAILED, null, null, null, null, null, -1);
            assertThat(metadataOnlyTool().extractCredentials(result).isEmpty()).isTrue();
        }

        @Test
        void missingIssuerProducesBothCredentials() {
            var sc = new SigstoreCredential.Builder()
                    .subject("alice@example.com")
                    .build();
            var result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, "alice@example.com", "EC",
                    sc, "12345", GeneralName.rfc822Name);

            List<Credential> credentials = metadataOnlyTool().extractCredentials(result);

            assertThat(credentials.size()).isEqualTo(2);
            assertThat(credentials.get(0)).isInstanceOf(SigstoreCredential.class);
            assertThat(credentials.get(1)).isInstanceOf(EmailCredential.class);
        }

        @Test
        void missingSubjectProducesNoCredentials() {
            var result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, null, "EC",
                    null, "12345", -1);

            assertThat(metadataOnlyTool().extractCredentials(result).isEmpty()).isTrue();
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
            assertThatThrownBy(() -> metadataOnlyTool().sign(null, null))
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
