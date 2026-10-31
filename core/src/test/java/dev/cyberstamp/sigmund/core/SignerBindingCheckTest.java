package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SignerBindingCheckTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final String OTHER_FP = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";
    private static final String ADDRESS = "alice@example.com";
    private static final String DIRECTORY = IssuerKind.KEYS_OPENPGP_ORG;
    private static final String GITHUB = "https://token.actions.githubusercontent.com";
    private static final String SUBJECT = "repo:acme/lib:ref:refs/heads/main";
    private static final String REPOSITORY = "https://github.com/acme/lib";
    private static final String REPOSITORY_ATTRIBUTE = "source-repository-uri";

    @TempDir
    Path dir;

    private final FakeDirectory directory = new FakeDirectory();
    private Path artifact;
    private Path signature;

    @BeforeEach
    void writeFiles() throws IOException {
        artifact = Files.writeString(dir.resolve("lib-1.0.jar"), "artifact");
        signature = Files.writeString(dir.resolve("lib-1.0.jar.asc"), "signature");
    }

    @Nested
    class PinnedKeys {

        @Test
        void aPinnedKeyPasses() {
            SignerIdentity alice = signer(KeyCredential.openPgp(FP));

            assertThatCode(() -> check(alice, true, verifiedBy(FP))).doesNotThrowAnyException();
        }

        @Test
        void aLowerCasePinnedFingerprintPasses() {
            SignerIdentity alice = signer(KeyCredential.openPgp(FP.toLowerCase()));

            assertThatCode(() -> check(alice, true, verifiedBy(FP))).doesNotThrowAnyException();
        }

        @Test
        void aKeyUnderMembersPasses() {
            SigmundConfig config = SigmundConfigParser.parse("<test>", new StringReader("""
                    signers:
                      alice:
                        members:
                          - pgp4: "%s"
                    """.formatted(FP)));
            SignerIdentity alice = config.signers().get("alice").withIssuersResolved(List.of());

            assertThatCode(() -> check(alice, true, verifiedBy(FP))).doesNotThrowAnyException();
        }

        @Test
        void anotherKeyFailsNamingBoth() {
            SignerIdentity alice = signer(KeyCredential.openPgp(FP));

            assertThatThrownBy(() -> check(alice, true, verifiedBy(OTHER_FP)))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("Signature by test-tool")
                    .hasMessageContaining("signer 'alice'")
                    .hasMessageContaining("pgp4 " + OTHER_FP)
                    .hasMessageContaining("pgp4 " + FP);
        }

        @Test
        void anUnverifiedSignatureFails() {
            SignerIdentity alice = signer(KeyCredential.openPgp(FP));
            TestTool tool = new TestTool(
                    OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM),
                    List.of());

            assertThatThrownBy(() -> check(alice, true, tool))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("signer 'alice'")
                    .hasMessageContaining("did not verify")
                    .hasMessageContaining("unsupported-algorithm");
        }

        @Test
        void aFailedSignatureFails() {
            SignerIdentity alice = signer(KeyCredential.openPgp(FP));
            TestTool tool = new TestTool(
                    OpenPgpVerifyResult.failed(null, "EdDSA", 4, null, FP), List.of());

            assertThatThrownBy(() -> check(alice, true, tool))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("did not verify (FAILED)");
        }

        @Test
        void aFileWithNoClaimFails() {
            SignerIdentity alice = signer(KeyCredential.openPgp(FP));
            TestTool tool = verifiedBy(FP);
            tool.claims = List.of();

            assertThatThrownBy(() -> check(alice, true, tool))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("signer 'alice'")
                    .hasMessageContaining("no signature");
        }

        @Test
        void anotherToolOfTheFormatVerifiesWhenTheProducerCannot() {
            SignerIdentity alice = signer(KeyCredential.openPgp(FP));
            TestTool producer = new TestTool(
                    OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM),
                    List.of());
            TestTool verifier = verifiedBy(FP);
            SignerBindingCheck check = new SignerBindingCheck(alice, directories(), true,
                    List.of(producer, verifier));

            assertThatCode(() -> check.check(artifact, producer, signature))
                    .doesNotThrowAnyException();
            assertThat(producer.verifications).isEqualTo(1);
        }
    }

    @Nested
    class DirectoryAddresses {

        private final SignerIdentity alice = new SignerIdentity("alice",
                List.of(IdentityCredential.email(null, ADDRESS)))
                .withIssuersResolved(List.of(DIRECTORY));

        @Test
        void aDirectoryConfirmedKeyPasses() {
            directory.addresses.put(OTHER_FP, List.of(ADDRESS));

            assertThatCode(() -> check(alice, true, verifiedBy(OTHER_FP)))
                    .doesNotThrowAnyException();
        }

        @Test
        void aDirectoryNotConfirmingFails() {
            directory.addresses.put(OTHER_FP, List.of("mallory@example.com"));

            assertThatThrownBy(() -> check(alice, true, verifiedBy(OTHER_FP)))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("signer 'alice'")
                    .hasMessageContaining("it proved pgp4 " + OTHER_FP)
                    .hasMessageContaining("mallory@example.com")
                    .hasMessageContaining(ADDRESS);
        }

        @Test
        void anUnreachableDirectoryFails() {
            directory.failing = true;

            assertThatThrownBy(() -> check(alice, true, verifiedBy(OTHER_FP)))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("signer 'alice'")
                    .hasMessageContaining("could not be asked")
                    .hasMessageContaining("pgp4 " + OTHER_FP);
        }

        @Test
        void lookupsDisabledFailNamingTheSetting() {
            directory.addresses.put(OTHER_FP, List.of(ADDRESS));

            assertThatThrownBy(() -> check(alice, false, verifiedBy(OTHER_FP)))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("signer 'alice'")
                    .hasMessageContaining("pgp4 " + OTHER_FP)
                    .hasMessageContaining("resolve-signers is false");
            assertThat(directory.asked).isEmpty();
        }
    }

    @Nested
    class SigstoreIdentities {

        private final SignerIdentity ci = new SignerIdentity("ci", List.of(
                new IdentityCredential(null, Map.of(REPOSITORY_ATTRIBUTE, REPOSITORY))))
                .withIssuersResolved(List.of(DIRECTORY, GITHUB));

        @Test
        void aSigstoreIdentityMatchesWithDefaultIssuers() {
            assertThatCode(() -> check(ci, true, provingRepository(REPOSITORY)))
                    .doesNotThrowAnyException();
        }

        @Test
        void anotherRepositoryFails() {
            assertThatThrownBy(() -> check(ci, true,
                    provingRepository("https://github.com/mallory/lib")))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("signer 'ci'")
                    .hasMessageContaining("https://github.com/mallory/lib");
        }

        private TestTool provingRepository(String repository) {
            return new TestTool(OpenPgpVerifyResult.verified(null, "EdDSA", 4, null, FP),
                    List.of(new IdentityCredential(GITHUB, Map.of(
                            IdentityCredential.SUBJECT, SUBJECT,
                            REPOSITORY_ATTRIBUTE, repository))));
        }
    }

    private void check(SignerIdentity signer, boolean lookupsEnabled, TestTool producer) {
        new SignerBindingCheck(signer, directories(), lookupsEnabled, List.of())
                .check(artifact, producer, signature);
    }

    private Map<String, OpenPgpDirectory> directories() {
        return Map.of(DIRECTORY, directory);
    }

    private static SignerIdentity signer(Credential credential) {
        return new SignerIdentity("alice", List.of(credential));
    }

    private static TestTool verifiedBy(String fingerprint) {
        return new TestTool(OpenPgpVerifyResult.verified(null, "EdDSA", 4, null, fingerprint),
                List.of(KeyCredential.openPgp(fingerprint)));
    }

    private static final class TestFormat implements SignatureFormat {

        static final String NAME = "test-format";

        private final TestTool tool;

        TestFormat(TestTool tool) {
            this.tool = tool;
        }

        @Override
        public String name() {
            return NAME;
        }

        @Override
        public String fileExtension() {
            return ".asc";
        }

        @Override
        public boolean canHandleByContent(Evidence evidence) {
            return true;
        }

        @Override
        public List<Claim> parse(Evidence evidence) {
            return tool.claims;
        }
    }

    private static final class TestTool implements SignatureTool {

        private final VerifyResult result;
        private final List<Credential> proven;
        private final TestFormat format = new TestFormat(this);
        List<Claim> claims = List.of(new OpenPgpClaim("block", 4, null, 22, Instant.EPOCH));
        int verifications;

        TestTool(VerifyResult result, List<Credential> proven) {
            this.result = result;
            this.proven = proven;
        }

        @Override
        public String name() {
            return "test-tool";
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return true;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return format;
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of(Credential.TYPE_PGP4);
        }

        @Override
        public boolean canVerify(Claim claim) {
            return true;
        }

        @Override
        public SignResult sign(Path artifactFile, Path outputSig, SigningInfo key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path artifactFile, Claim claim) {
            verifications++;
            return result;
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult verified) {
            return verified.isVerified() ? proven : List.of();
        }
    }

    private static final class FakeDirectory implements OpenPgpDirectory {
        final Map<String, List<String>> addresses = new HashMap<>();
        final List<String> asked = new ArrayList<>();
        boolean failing;

        @Override
        public String name() {
            return DIRECTORY;
        }

        @Override
        public List<String> verifiedAddresses(String fingerprint) throws IOException {
            asked.add(fingerprint);
            if (failing) {
                throw new IOException("unreachable");
            }
            return addresses.getOrDefault(fingerprint, List.of());
        }
    }
}
