package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringReader;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SigmundConfigParserTest {

    private SigmundConfig parse(String yaml) {
        return SigmundConfigParser.parse("<test>", new StringReader(yaml));
    }

    @Nested
    class SignerParsing {

        @Test
        void minimalSignerEmailString() {
            var config = parse("""
                    signers:
                      bob: "bob@example.com"
                    """);
            var bob = config.signers().get("bob");
            assertThat(bob).isNotNull();
            assertThat(bob.displayName()).isEqualTo("bob");
            assertThat(bob.credentials().size()).isEqualTo(1);
            assertThat(bob.credentials().get(0)).isInstanceOf(EmailCredential.class);
            assertThat(((EmailCredential) bob.credentials().get(0)).email()).isEqualTo("bob@example.com");
        }

        @Test
        void objectSignerWithFingerprints() {
            var config = parse("""
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        openpgp4: "4AEE18F83AFDEB23"
                        openpgp6: "ABCD1234ABCD1234"
                    """);
            var alice = config.signers().get("alice");
            assertThat(alice.displayName()).isEqualTo("Alice");
            assertThat(alice.credentials().size()).isEqualTo(3);

            var types = alice.credentials().stream().map(Credential::type).toList();
            assertThat(types.contains("openpgp4")).isTrue();
            assertThat(types.contains("openpgp6")).isTrue();
            assertThat(types.contains("email")).isTrue();
        }

        @Test
        void objectSignerWithSigstoreRepoUri() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        name: "CI Pipeline"
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          source-repository-uri: "https://github.com/org/repo"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.displayName()).isEqualTo("CI Pipeline");
            assertThat(ci.credentials().size()).isEqualTo(1);
            assertThat(ci.credentials().get(0)).isInstanceOf(SigstoreCredential.class);
            var sc = (SigstoreCredential) ci.credentials().get(0);
            assertThat(sc.issuer()).isEqualTo("https://token.actions.githubusercontent.com");
            assertThat(sc.sourceRepositoryUri()).isEqualTo("https://github.com/org/repo");
            assertThat(sc.subject()).isNull();
        }

        @Test
        void objectSignerWithSigstoreSubject() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          subject: "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().get(0)).isInstanceOf(SigstoreCredential.class);
            var sc = (SigstoreCredential) ci.credentials().get(0);
            assertThat(sc.subject()).isEqualTo(
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0");
        }

        @Test
        void sigstoreUnknownFieldThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci-pipeline:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          oidc-subject: "https://github.com/org/repo"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("oidc-subject");
        }

        @Test
        void objectSignerWithSigstoreAllFields() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          source-repository-uri: "https://github.com/org/repo"
                          build-trigger: "release"
                          build-config-uri: "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"
                          runner-environment: "github-hosted"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().get(0)).isInstanceOf(SigstoreCredential.class);
            var sc = (SigstoreCredential) ci.credentials().get(0);
            assertThat(sc.issuer()).isEqualTo("https://token.actions.githubusercontent.com");
            assertThat(sc.sourceRepositoryUri()).isEqualTo("https://github.com/org/repo");
            assertThat(sc.buildTrigger()).isEqualTo("release");
            assertThat(sc.buildConfigUri()).isEqualTo(
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main");
            assertThat(sc.runnerEnvironment()).isEqualTo("github-hosted");
        }

        @Test
        void pgp4Canonical() {
            var config = parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23"
                    """);
            var fp = (FingerprintCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp4");
        }

        @Test
        void pgp6Canonical() {
            var config = parse("""
                    signers:
                      alice:
                        pgp6: "ABCD1234ABCD1234"
                    """);
            var fp = (FingerprintCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp6");
        }

        @Test
        void openpgp4Alias() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp4: "4AEE18F83AFDEB23"
                    """);
            var fp = (FingerprintCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp4");
        }

        @Test
        void openpgp6Alias() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp6: "ABCD1234ABCD1234"
                    """);
            var fp = (FingerprintCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("openpgp6");
        }

        @Test
        void objectSignerWithEmailAndFingerprint() {
            var config = parse("""
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23"
                    """);
            var alice = config.signers().get("alice");
            assertThat(alice.displayName()).isEqualTo("Alice");
            assertThat(alice.credentials().stream()
                    .anyMatch(c -> c instanceof EmailCredential ec && ec.email().equals("alice@example.com")))
                    .isTrue();
        }

        @Test
        void organizationWithMembers() {
            var config = parse("""
                    signers:
                      apache:
                        name: "Apache Software Foundation"
                        members:
                          - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            email: "dev@maven.apache.org"
                          - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    """);
            var apache = config.signers().get("apache");
            assertThat(apache.displayName()).isEqualTo("Apache Software Foundation");
            assertThat(apache.credentials().size()).isEqualTo(3);

            var fps = apache.credentials().stream()
                    .filter(c -> c instanceof FingerprintCredential)
                    .map(c -> ((FingerprintCredential) c).fingerprint())
                    .toList();
            assertThat(fps.size()).isEqualTo(2);
            assertThat(fps.contains("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")).isTrue();
            assertThat(fps.contains("BBE7232D7991050B54C8EA0ADC08637CA615D22C")).isTrue();

            assertThat(apache.credentials().stream()
                    .anyMatch(c -> c instanceof EmailCredential ec && ec.email().equals("dev@maven.apache.org")))
                    .isTrue();
        }

        @Test
        void membersWithMultipleCredentialTypes() {
            var config = parse("""
                    signers:
                      team:
                        name: "Release Team"
                        members:
                          - openpgp4: "AAAA1111AAAA1111"
                            openpgp6: "BBBB2222BBBB2222"
                            email: "alice@example.com"
                    """);
            var team = config.signers().get("team");
            assertThat(team.credentials().size()).isEqualTo(3);

            var types = team.credentials().stream().map(Credential::type).toList();
            assertThat(types.contains("openpgp4")).isTrue();
            assertThat(types.contains("openpgp6")).isTrue();
            assertThat(types.contains("email")).isTrue();
        }

        @Test
        void topLevelCredentialsCombinedWithMembers() {
            var config = parse("""
                    signers:
                      org:
                        name: "My Org"
                        email: "org@example.com"
                        members:
                          - openpgp4: "CCCC3333CCCC3333"
                    """);
            var org = config.signers().get("org");
            assertThat(org.credentials().size()).isEqualTo(2);
            assertThat(org.credentials().stream()
                    .anyMatch(c -> c instanceof EmailCredential ec && ec.email().equals("org@example.com")))
                    .isTrue();
            assertThat(org.credentials().stream()
                    .anyMatch(c -> c instanceof FingerprintCredential fc
                            && fc.fingerprint().equals("CCCC3333CCCC3333")))
                    .isTrue();
        }

        @Test
        void emptyMembersWithNoTopLevelCredentialsThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      empty-org:
                        name: "Empty Org"
                        members: []
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void nestedMembersThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bad-org:
                        name: "Bad Org"
                        members:
                          - openpgp4: "AAAA1111AAAA1111"
                            members:
                              - openpgp4: "BBBB2222BBBB2222"
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void membersNotArrayThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bad-org:
                        name: "Bad Org"
                        members: "not-an-array"
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }
    }

    @Nested
    class TrustParsing {

        @Test
        void artifactGroupsExpandInTrust() {
            String yaml = """
                    signers:
                      alice: "alice@example.com"
                    artifacts:
                      apache-stack:
                        - org.apache.maven.*
                        - org.apache.commons.*
                    trust:
                      apache-stack: alice
                    """;
            SigmundConfig config = SigmundConfigParser.parse("<test>", new StringReader(yaml));
            TrustPolicy policy = config.trustPolicy();
            // "apache-stack" should be expanded into its two patterns
            assertThat(policy.expectedSigners(
                    artifact("org.apache.maven.plugins", "maven-compiler-plugin", "3.13.0")).isEmpty())
                    .isFalse();
            assertThat(policy.expectedSigners(
                    artifact("org.apache.commons", "commons-lang3", "3.14")).isEmpty())
                    .isFalse();
            // A non-matching artifact should have no signers
            assertThat(policy.expectedSigners(
                    artifact("com.example", "lib", "1.0")).isEmpty())
                    .isTrue();
        }

        @Test
        void trustMappingsResolved() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp4: "4AEE18F83AFDEB23"
                    trust:
                      "org.example:*": [alice]
                    """);
            var artifact = artifact("org.example", "lib", "1.0");
            var expected = config.trustPolicy().expectedSigners(artifact);
            assertThat(expected.size()).isEqualTo(1);
            assertThat(expected.get(0).id()).isEqualTo("alice");
        }

        @Test
        void trustMappingsSingleString() {
            var config = parse("""
                    signers:
                      bob: "bob@example.com"
                    trust:
                      "org.example:lib": bob
                    """);
            var expected = config.trustPolicy().expectedSigners(artifact("org.example", "lib", "1.0"));
            assertThat(expected.size()).isEqualTo(1);
            assertThat(expected.get(0).id()).isEqualTo("bob");
        }

        @Test
        void trustMappingsUndefinedSignerThrows() {
            assertThatThrownBy(() -> parse("""
                    trust:
                      "org.example:*": [nonexistent]
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void memberCredentialMatchesTrust() {
            var config = parse("""
                    signers:
                      apache:
                        name: "Apache Software Foundation"
                        members:
                          - openpgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                          - openpgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    trust:
                      "org.apache.*": apache
                    """);
            var expected = config.trustPolicy().expectedSigners(
                    artifact("org.apache.maven.plugins", "maven-compiler-plugin", "3.13.0"));
            assertThat(expected.size()).isEqualTo(1);
            assertThat(expected.get(0).id()).isEqualTo("apache");

            var creds = expected.get(0).credentials();
            assertThat(creds.size()).isEqualTo(2);
            assertThat(creds.stream()
                    .anyMatch(c -> c instanceof FingerprintCredential fc
                            && fc.fingerprint().equals("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")))
                    .isTrue();
            assertThat(creds.stream()
                    .anyMatch(c -> c instanceof FingerprintCredential fc
                            && fc.fingerprint().equals("BBE7232D7991050B54C8EA0ADC08637CA615D22C")))
                    .isTrue();
        }

        @Test
        void signatureOptionalAllowed() {
            var config = parse("""
                    signature-optional:
                      - "org.example:optional-lib"
                    """);
            assertThat(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "optional-lib", "1.0"))).isTrue();
            assertThat(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "other-lib", "1.0"))).isFalse();
        }
    }

    @Nested
    class PolicyParsing {

        @Test
        void defaults() {
            var config = parse("version: 1");
            assertThat(config.trustPolicy().listedEvidence()).isEqualTo(ListedEvidencePolicy.ALL);
            assertThat(config.trustPolicy().unlistedEvidence()).isEqualTo(UnlistedEvidencePolicy.IGNORE);
            assertThat(config.trustPolicy().onUntrusted()).isEqualTo(UntrustedPolicy.FAIL);
        }

        @Test
        void warnPolicy() {
            var config = parse("""
                    policy:
                      on-untrusted: warn
                      listed-evidence: any
                    """);
            assertThat(config.trustPolicy().onUntrusted()).isEqualTo(UntrustedPolicy.WARN);
            assertThat(config.trustPolicy().listedEvidence()).isEqualTo(ListedEvidencePolicy.ANY);
        }

        @Test
        void invalidPolicyThrows() {
            assertThatThrownBy(() -> parse("""
                    policy:
                      on-untrusted: ignore
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }
    }

    @Nested
    class SigningParsing {

        @Test
        void signingConfig() {
            var config = parse("""
                    signing:
                      signer: alice
                      credential-types: [pgp4, pgp6]
                      profiles:
                        classic: [pgp4]
                      toolchain: [sq]
                    tools:
                      sq:
                        cipher-suite: "mldsa87-ed448"
                    """);
            var signing = config.signingConfig();
            assertThat(signing.signer()).isEqualTo("alice");
            assertThat(signing.credentialTypes()).isEqualTo(List.of("pgp4", "pgp6"));
            assertThat(signing.profiles().get("classic")).isEqualTo(List.of("pgp4"));
            assertThat(signing.toolchain()).isEqualTo(List.of("sq"));
            assertThat(config.toolsConfig().get("sq").settings().get("cipher-suite")).isEqualTo("mldsa87-ed448");
        }

        @Test
        void noSigningSection() {
            var config = parse("version: 1");
            assertThat(config.signingConfig()).isEqualTo(SigningConfig.DEFAULT);
        }
    }

    @Nested
    class VerificationParsing {

        @Test
        void verificationConfig() {
            var config = parse("""
                    verification:
                      resolve-signers: true
                      import-to-keyring: false
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            var dc = config.discoveryConfig();
            assertThat(dc.resolveSigners()).isTrue();
            assertThat(dc.importToKeyring()).isFalse();
            assertThat(dc.keyservers()).isEqualTo(List.of("hkps://keys.openpgp.org"));
        }

        @Test
        void toolchainList() {
            var config = parse("""
                    verification:
                      toolchain: [sq, gpg]
                    """);
            assertThat(config.discoveryConfig().toolchain()).isEqualTo(List.of("sq", "gpg"));
        }

        @Test
        void toolchainScalar() {
            var config = parse("""
                    verification:
                      toolchain: gpg
                    """);
            assertThat(config.discoveryConfig().toolchain()).isEqualTo(List.of("gpg"));
        }

        @Test
        void toolchainDefault() {
            var config = parse("""
                    verification:
                      resolve-signers: true
                    """);
            assertThat(config.discoveryConfig().toolchain()).isNull();
            assertThat(config.discoveryConfig().effectiveToolchain()).isEqualTo(DiscoveryConfig.DEFAULT_TOOL_PRIORITY);
        }

        @Test
        void noVerificationSection() {
            var config = parse("version: 1");
            assertThat(config.discoveryConfig()).isEqualTo(DiscoveryConfig.DEFAULT);
        }
    }

    @Nested
    class ToolsParsing {

        @Test
        void topLevelToolsConfig() {
            var config = parse("""
                    tools:
                      sigstore:
                        trusted-root: "/path/to/root.json"
                      bc:
                        gnupg-home: "/custom/gnupg"
                    """);
            var tc = config.toolsConfig();
            assertThat(tc.isEmpty()).isFalse();
            assertThat(tc.size()).isEqualTo(2);
            assertThat(tc.get("sigstore")).isNotNull();
            assertThat(tc.get("sigstore").settings().get("trusted-root")).isEqualTo("/path/to/root.json");
            assertThat(tc.get("bc")).isNotNull();
            assertThat(tc.get("bc").settings().get("gnupg-home")).isEqualTo("/custom/gnupg");
        }

        @Test
        void noToolsSection() {
            var config = parse("version: 1");
            assertThat(config.toolsConfig().isEmpty()).isTrue();
        }
    }

    @Nested
    class FullConfig {

        @Test
        void parsesCompleteConfig() {
            var config = parse("""
                    version: 1
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23"
                        pgp6: "ABCD1234ABCD1234"
                      bob: "bob@example.com"
                    signing:
                      signer: alice
                    trust:
                      "org.example:*": [alice, bob]
                    signature-optional:
                      - "org.example:optional-lib"
                    policy:
                      on-untrusted: fail
                    verification:
                      resolve-signers: true
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            assertThat(config.version()).isEqualTo(1);
            assertThat(config.signers().names().size()).isEqualTo(2);
            assertThat(config.signingConfig().signer()).isEqualTo("alice");
            assertThat(config.trustPolicy().listedEvidence()).isEqualTo(ListedEvidencePolicy.ALL);
            assertThat(config.discoveryConfig().resolveSigners()).isTrue();
        }
    }

    private static ArtifactCoords artifact(String ns, String name, String version) {
        return new ArtifactCoords(ns, name, "", "jar", version);
    }
}
