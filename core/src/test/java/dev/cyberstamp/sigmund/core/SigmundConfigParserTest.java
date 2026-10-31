package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringReader;
import java.util.List;
import java.util.Set;
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
                    issuers: [keys.openpgp.org]
                    signers:
                      bob: "bob@example.com"
                    """);
            var bob = config.signers().get("bob");
            assertThat(bob).isNotNull();
            assertThat(bob.credentials().size()).isEqualTo(1);
            assertThat(bob.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            assertThat(((IdentityCredential) bob.credentials().get(0)).attribute(IdentityCredential.EMAIL))
                    .isEqualTo("bob@example.com");
        }

        @Test
        void objectSignerWithFingerprints() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23000000000000000000000000"
                        pgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                    """);
            var alice = config.signers().get("alice");
            assertThat(alice.credentials().size()).isEqualTo(3);

            var types = alice.credentials().stream().map(Credential::type).toList();
            assertThat(types).contains("pgp4", "pgp6", Credential.TYPE_IDENTITY);
        }

        @Test
        void objectSignerWithIdentityRepoUri() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            source-repository-uri: "https://github.com/org/repo"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().size()).isEqualTo(1);
            assertThat(ci.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            var sc = (IdentityCredential) ci.credentials().get(0);
            assertThat(sc.issuer()).isEqualTo("https://token.actions.githubusercontent.com");
            assertThat(sc.attribute("source-repository-uri")).isEqualTo("https://github.com/org/repo");
            assertThat(sc.attribute(IdentityCredential.SUBJECT)).isNull();
        }

        @Test
        void objectSignerWithIdentitySubject() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            subject: "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            var sc = (IdentityCredential) ci.credentials().get(0);
            assertThat(sc.attribute(IdentityCredential.SUBJECT)).isEqualTo(
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0");
        }

        @Test
        void identityUnknownFieldThrowsAtCompile() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            oidc-subject: "https://github.com/org/repo"
                    """);
            assertThatThrownBy(() -> RulePolicy.compile(config.trustPolicySpec(), config.signers()))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("oidc-subject");
        }

        @Test
        void misspelledAttributeSuggestsTheKnownName() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            build-config-ur: "https://github.com/org/repo/.github/workflows/release.yml"
                    """);
            assertThatThrownBy(() -> RulePolicy.compile(config.trustPolicySpec(), config.signers()))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("did you mean 'build-config-uri'");
        }

        @Test
        void extensionFromTheFulcioRegistryIsAccepted() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            source-repository-ref: "refs/heads/main"
                    """);
            var sc = (IdentityCredential) config.signers().get("ci-pipeline").credentials().get(0);
            assertThat(sc.attribute("source-repository-ref")).isEqualTo("refs/heads/main");
        }

        @Test
        void identityWithOnlyAnIssuerThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("at least one attribute besides its issuer");
        }

        @Test
        void identityWithoutIssuerNeedsAListedOidcIssuer() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        identities:
                          - source-repository-uri: "https://github.com/org/repo"
                    """);
            assertThatThrownBy(() -> RulePolicy.compile(config.trustPolicySpec(), config.signers()))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("no listed issuer can assert source-repository-uri");
        }

        @Test
        void unclassifiableIssuersTheAssertedSignerDoesNotUseDoNotStopTheSigningPath() {
            var config = parse("""
                    issuers:
                      - keyserver.ubuntu.com
                    signers:
                      alice:
                        identities:
                          - issuer: "https://accounts.google.com"
                            email: alice@example.com
                      bob:
                        identities:
                          - issuer: oidc.example
                            email: bob@example.com
                    signing:
                      signer: alice
                    """);

            assertThat(config.signingConfig().signer()).isEqualTo("alice");
            assertThat(config.signers().get("bob")).isNotNull();
            assertThat(config.trustPolicySpec().issuers()).containsExactly("keyserver.ubuntu.com");
        }

        @Test
        void unclassifiableIssuerInTheListFailsWhenTheVerifierLoads() {
            var config = parse("""
                    issuers:
                      - keyserver.ubuntu.com
                    """);

            assertThatThrownBy(() -> RulePolicy.compile(config.trustPolicySpec(), config.signers()))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("Issuer 'keyserver.ubuntu.com' in 'issuers'")
                    .hasMessageContaining("neither a known directory");
        }

        @Test
        void unclassifiableInlineIssuerFailsWhenTheVerifierLoadsNamingTheSigner() {
            var config = parse("""
                    signers:
                      alice:
                        identities:
                          - issuer: oidc.example
                            email: alice@example.com
                    """);

            assertThatThrownBy(() -> RulePolicy.compile(config.trustPolicySpec(), config.signers()))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("Issuer 'oidc.example' in signer 'alice'")
                    .hasMessageContaining("neither a known directory");
        }

        @Test
        void knownDirectoryWithoutSchemeIsListedByItsUrl() {
            var config = parse("""
                    issuers:
                      - keys.openpgp.org
                      - https://keys.openpgp.org/
                    """);
            assertThat(config.trustPolicySpec().issuers()).containsExactly("https://keys.openpgp.org");
        }

        @Test
        void emailWithoutAnyIssuerThrows() {
            var config = parse("""
                    signers:
                      alice:
                        email: "alice@example.com"
                    """);
            assertThatThrownBy(() -> RulePolicy.compile(config.trustPolicySpec(), config.signers()))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("no listed issuer can assert email")
                    .hasMessageContaining("keys.openpgp.org");
        }

        @Test
        void identityNamesItsOwnIssuerWithoutListingIt() {
            var config = parse("""
                    signers:
                      bot:
                        identities:
                          - issuer: "https://accounts.google.com"
                            email: "bot@example.com"
                    """);
            var identity = (IdentityCredential) config.signers().get("bot").credentials().get(0);
            assertThat(identity.issuer()).isEqualTo("https://accounts.google.com");
            assertThat(identity.attribute(IdentityCredential.EMAIL)).isEqualTo("bot@example.com");
            assertThat(config.trustPolicySpec().issuers()).isEmpty();
        }

        @Test
        void emailIsAnAddressOnly() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bot:
                        email:
                          address: "bot@example.com"
                          issuer: "https://accounts.google.com"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("to name its issuer, use 'identities'");
        }

        @Test
        void unknownSignerKeyThrowsRatherThanDroppingACredential() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      ci:
                        sigstore:
                          issuer: "https://token.actions.githubusercontent.com"
                          source-repository-uri: "https://github.com/org/repo"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("unknown key 'sigstore'");
        }

        @Test
        void nameIsNotASignerKey() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      alice:
                        name: "Alice"
                        pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("unknown key 'name'");
        }

        @Test
        void oneSignerMayCarrySeveralIdentities() {
            var config = parse("""
                    signers:
                      alice:
                        identities:
                          - issuer: keys.openpgp.org
                            email: "alice@example.com"
                          - issuer: "https://accounts.google.com"
                            email: "alice@example.com"
                    """);
            var issuers = config.signers().get("alice").credentials().stream()
                    .map(c -> ((IdentityCredential) c).issuer())
                    .toList();
            assertThat(issuers).containsExactly(IssuerKind.KEYS_OPENPGP_ORG, "https://accounts.google.com");
        }

        @Test
        void inlineDirectoryCannotAssertWorkflowAttributes() {
            var config = parse("""
                    signers:
                      ci:
                        identities:
                          - issuer: keys.openpgp.org
                            source-repository-uri: "https://github.com/org/repo"
                    """);
            assertThatThrownBy(() -> RulePolicy.compile(config.trustPolicySpec(), config.signers()))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("issuer 'https://keys.openpgp.org' cannot assert source-repository-uri");
        }

        @Test
        void keyIdIsRejectedAsAFingerprint() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("Signer 'alice'")
                    .hasMessageContaining("not a full fingerprint");
        }

        @Test
        void identityWithoutIssuerUsesTheList() {
            var config = parse("""
                    issuers:
                      - https://token.actions.githubusercontent.com
                    signers:
                      ci-pipeline:
                        identities:
                          - source-repository-uri: "https://github.com/org/repo"
                    """);
            var sc = (IdentityCredential) config.signers().get("ci-pipeline").credentials().get(0);
            assertThat(sc.issuer()).isNull();
            assertThat(config.trustPolicySpec().issuers())
                    .containsExactly("https://token.actions.githubusercontent.com");
        }

        @Test
        void objectSignerWithIdentityAllFields() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      ci-pipeline:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            source-repository-uri: "https://github.com/org/repo"
                            build-trigger: "release"
                            build-config-uri: "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"
                            runner-environment: "github-hosted"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertThat(ci.credentials().get(0)).isInstanceOf(IdentityCredential.class);
            var sc = (IdentityCredential) ci.credentials().get(0);
            assertThat(sc.issuer()).isEqualTo("https://token.actions.githubusercontent.com");
            assertThat(sc.attribute("source-repository-uri")).isEqualTo("https://github.com/org/repo");
            assertThat(sc.attribute("build-trigger")).isEqualTo("release");
            assertThat(sc.attribute("build-config-uri")).isEqualTo(
                    "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main");
            assertThat(sc.attribute("runner-environment")).isEqualTo("github-hosted");
        }

        @Test
        void pgp4Canonical() {
            var config = parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23000000000000000000000000"
                    """);
            var fp = (KeyCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("pgp4");
        }

        @Test
        void pgp6Canonical() {
            var config = parse("""
                    signers:
                      alice:
                        pgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                    """);
            var fp = (KeyCredential) config.signers().get("alice").credentials().get(0);
            assertThat(fp.type()).isEqualTo("pgp6");
        }

        @Test
        void openpgp4IsNotASignerKey() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      alice:
                        openpgp4: "4AEE18F83AFDEB23000000000000000000000000"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("unknown key 'openpgp4'")
                    .hasMessageContaining("pgp4");
        }

        @Test
        void openpgp6IsNotASignerKey() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      alice:
                        openpgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("unknown key 'openpgp6'");
        }

        @Test
        void aSignerThatRotatedKeysListsEveryFingerprint() {
            var config = parse("""
                    signers:
                      jane:
                        pgp4: ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"]
                        pgp6: ["ABCD1234ABCD1234000000000000000000000000000000000000000000000000"]
                        email: "jane@example.com"
                    """);
            assertThat(config.signers().get("jane").credentials())
                    .filteredOn(KeyCredential.class::isInstance)
                    .extracting(credential -> ((KeyCredential) credential).fingerprint())
                    .containsExactly("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                            "ABCD1234ABCD1234000000000000000000000000000000000000000000000000");
        }

        @Test
        void aMemberMayListSeveralFingerprints() {
            var config = parse("""
                    signers:
                      acme:
                        members:
                          - pgp4: ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"]
                    """);
            assertThat(config.signers().get("acme").credentials()).hasSize(2);
        }

        @Test
        void aFingerprintThatIsAMappingIsErrorRatherThanDropped() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      jane:
                        pgp4: { fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
                        email: "jane@example.com"
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("Signer 'jane': 'pgp4' must be a fingerprint or a list of fingerprints");
        }

        @Test
        void aFingerprintListEntryThatIsNotAStringIsError() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      jane:
                        pgp6: [["ABCD1234ABCD1234000000000000000000000000000000000000000000000000"]]
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("Signer 'jane': 'pgp6' must be a fingerprint or a list of fingerprints");
        }

        @Test
        void objectSignerWithEmailAndFingerprint() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23000000000000000000000000"
                    """);
            var alice = config.signers().get("alice");
            assertThat(alice.credentials().stream()
                    .anyMatch(c -> c instanceof IdentityCredential ec
                            && ec.attribute(IdentityCredential.EMAIL).equals("alice@example.com")))
                    .isTrue();
        }

        @Test
        void organizationWithMembers() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      apache:
                        members:
                          - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            email: "dev@maven.apache.org"
                          - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    """);
            var apache = config.signers().get("apache");
            assertThat(apache.credentials().size()).isEqualTo(3);

            var fps = apache.credentials().stream()
                    .filter(c -> c instanceof KeyCredential)
                    .map(c -> ((KeyCredential) c).fingerprint())
                    .toList();
            assertThat(fps.size()).isEqualTo(2);
            assertThat(fps.contains("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")).isTrue();
            assertThat(fps.contains("BBE7232D7991050B54C8EA0ADC08637CA615D22C")).isTrue();

            assertThat(apache.credentials().stream()
                    .anyMatch(c -> c instanceof IdentityCredential ec
                            && ec.attribute(IdentityCredential.EMAIL).equals("dev@maven.apache.org")))
                    .isTrue();
        }

        @Test
        void membersWithMultipleCredentialTypes() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      team:
                        members:
                          - pgp4: "AAAA1111AAAA1111000000000000000000000000"
                            pgp6: "BBBB2222BBBB2222000000000000000000000000000000000000000000000000"
                            email: "alice@example.com"
                    """);
            var team = config.signers().get("team");
            assertThat(team.credentials().size()).isEqualTo(3);

            var types = team.credentials().stream().map(Credential::type).toList();
            assertThat(types).contains("pgp4", "pgp6", Credential.TYPE_IDENTITY);
        }

        @Test
        void topLevelCredentialsCombinedWithMembers() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      org:
                        email: "org@example.com"
                        members:
                          - pgp4: "CCCC3333CCCC3333000000000000000000000000"
                    """);
            var org = config.signers().get("org");
            assertThat(org.credentials().size()).isEqualTo(2);
            assertThat(org.credentials().stream()
                    .anyMatch(c -> c instanceof IdentityCredential ec
                            && ec.attribute(IdentityCredential.EMAIL).equals("org@example.com")))
                    .isTrue();
            assertThat(org.credentials().stream()
                    .anyMatch(c -> c instanceof KeyCredential fc
                            && fc.fingerprint().equals("CCCC3333CCCC3333000000000000000000000000")))
                    .isTrue();
        }

        @Test
        void emptyMembersWithNoTopLevelCredentialsThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      empty-org:
                        members: []
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void nestedMembersThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bad-org:
                        members:
                          - pgp4: "AAAA1111AAAA1111000000000000000000000000"
                            members:
                              - pgp4: "BBBB2222BBBB2222000000000000000000000000"
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void membersNotArrayThrows() {
            assertThatThrownBy(() -> parse("""
                    signers:
                      bad-org:
                        members: "not-an-array"
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }
    }

    @Nested
    class RulesParsing {

        @Test
        void artifactSetsKeyParsed() {
            var config = parse("""
                    artifact-sets:
                      apache-stack: [org.apache.maven.*]
                    """);
            assertThat(config.artifactSets().get("apache-stack")).containsExactly("org.apache.maven.*");
        }

        @Test
        void rulesParsedToSpec() {
            var doc = parse("""
                    rules:
                      - match: ["com.acme.*"]
                        requires: [acme-release, {any-of: [ci-a, ci-b]}]
                        on-no-claim: ignore
                    """).trustPolicySpec();
            assertThat(doc.rules()).hasSize(1);
            assertThat(doc.rules().get(0).clauseIds())
                    .containsExactly(Set.of("acme-release"), Set.of("ci-a", "ci-b"));
            assertThat(doc.rules().get(0).enforcement())
                    .containsEntry(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE);
            assertThat(doc.declared()).isTrue();
        }

        @Test
        void matchExpandsArtifactSetNames() {
            var doc = parse("""
                    artifact-sets:
                      apache-stack:
                        - org.apache.maven.*
                        - org.apache.commons.*
                    rules:
                      - match: [apache-stack]
                        requires: [alice]
                    """).trustPolicySpec();
            assertThat(doc.rules().get(0).patterns())
                    .containsExactly(ArtifactPattern.parse("org.apache.maven.*"),
                            ArtifactPattern.parse("org.apache.commons.*"));
        }

        @Test
        void inlinePatternAndArtifactSetMayMix() {
            var doc = parse("""
                    artifact-sets:
                      stack: [org.apache.maven.*]
                    rules:
                      - match: [stack, "com.acme:lib"]
                        requires: [alice]
                    """).trustPolicySpec();
            assertThat(doc.rules().get(0).patterns())
                    .containsExactly(ArtifactPattern.parse("org.apache.maven.*"),
                            ArtifactPattern.parse("com.acme:lib"));
        }

        @Test
        void signingOnlyConfigIsNotAPolicy() {
            var doc = parse("""
                    issuers: [keys.openpgp.org]
                    signers: { alice: "alice@example.com" }
                    signing: { signer: alice }
                    """).trustPolicySpec();
            assertThat(doc.declared()).isFalse();
        }

        @Test
        void emptyRulesIsAPolicy() {
            assertThat(parse("rules: []").trustPolicySpec().declared()).isTrue();
        }

        @Test
        void defaultsWithoutRulesIsErrorRatherThanSwitchingEnforcementOn() {
            assertThatThrownBy(() -> parse("""
                    signing: { toolchain: [bc] }
                    defaults: { extra-claims: ignore }
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("'defaults' has no effect without 'rules'");
        }

        @Test
        void misspelledArtifactSetIsErrorSuggestingTheNearestSet() {
            assertThatThrownBy(() -> parse("""
                    artifact-sets:
                      apache-stack: [org.apache.maven.*]
                    rules:
                      - match: [apache-stak]
                        requires: [alice]
                    """))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("rules[0]")
                    .hasMessageContaining("'apache-stak'")
                    .hasMessageContaining("did you mean 'apache-stack'");
        }

        @Test
        void undefinedArtifactSetIsErrorExplainingTheSingleWordGroupForm() {
            assertThatThrownBy(() -> parse("rules: [{ match: [junit], requires: [alice] }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("not a defined artifact-set")
                    .hasMessageContaining("'junit:*'");
        }

        @Test
        void singleWordGroupIsWrittenWithAnArtifactWildcard() {
            var doc = parse("rules: [{ match: [\"junit:*\"], requires: [alice] }]")
                    .trustPolicySpec();
            assertThat(doc.rules().get(0).patterns())
                    .containsExactly(ArtifactPattern.parse("junit:*"));
        }

        @Test
        void dottedGroupIsAPatternNotASetReference() {
            var doc = parse("rules: [{ match: [com.acme], requires: [alice] }]")
                    .trustPolicySpec();
            assertThat(doc.rules().get(0).patterns())
                    .containsExactly(ArtifactPattern.parse("com.acme"));
        }

        @Test
        void anyOfEntryThatIsAMappingIsError() {
            assertThatThrownBy(() -> parse(
                    "rules: [{ match: [\"*\"], requires: [{any-of: [alice, {name: bob}]}] }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("rules[0]")
                    .hasMessageContaining("must be signer ids")
                    .hasMessageContaining("mapping");
        }

        @Test
        void nestedAnyOfIsErrorNamingTheShape() {
            assertThatThrownBy(() -> parse(
                    "rules: [{ match: [\"*\"], requires: [{any-of: [alice, {any-of: [bob]}]}] }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("nested 'any-of' is not supported");
        }

        @Test
        void nullAnyOfEntryIsError() {
            assertThatThrownBy(() -> parse(
                    "rules: [{ match: [\"*\"], requires: [{any-of: [alice, null]}] }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("must be signer ids");
        }

        @Test
        void blankSignerReferenceIsError() {
            assertThatThrownBy(() -> parse("rules: [{ match: [\"*\"], requires: [\"\"] }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("blank");
            assertThatThrownBy(() -> parse(
                    "rules: [{ match: [\"*\"], requires: [{any-of: [\" \"]}] }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("blank");
        }

        @Test
        void numericSignerIdIsAReference() {
            var doc = parse("rules: [{ match: [\"*\"], requires: [{any-of: [123]}] }]")
                    .trustPolicySpec();
            assertThat(doc.rules().get(0).clauseIds()).containsExactly(Set.of("123"));
        }

        @Test
        void emptyRequiresIsError() {
            assertThatThrownBy(() -> parse("rules: [{ match: [\"*\"], requires: [] }]"))
                    .isInstanceOf(PolicyConfigException.class).hasMessageContaining("requires");
        }

        @Test
        void scalarRequiresIsOneClause() {
            var rule = parse("rules: [{ match: \"*\", requires: a }]").trustPolicySpec().rules().get(0);
            assertThat(rule.clauseIds()).containsExactly(Set.of("a"));
        }

        @Test
        void requiresThatIsAMappingIsError() {
            assertThatThrownBy(() -> parse("rules: [{ match: [\"*\"], requires: { a: b } }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("'requires' must be a signer id or a list of clauses");
        }

        @Test
        void requiresMayBeOmittedForACatchAll() {
            var doc = parse("""
                    rules:
                      - match: ["*"]
                        on-no-claim: ignore
                    """).trustPolicySpec();
            assertThat(doc.rules().get(0).clauseIds()).isEmpty();
        }

        @Test
        void fourSegmentPatternIsError() {
            assertThatThrownBy(() -> parse("rules: [{ match: [\"a:b:c:d\"], requires: [a] }]"))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void unknownRuleKeyIsError() {
            assertThatThrownBy(() -> parse("""
                    rules:
                      - match: ["*"]
                        requires: [a]
                        on-bogus: warn
                    """))
                    .isInstanceOf(PolicyConfigException.class);
        }

        @Test
        void extraClaimsDefaultsToReject() {
            assertThat(parse("rules: [{ match: [\"*\"], requires: [a] }]")
                    .trustPolicySpec().extraClaims()).isEqualTo(ClaimSetMode.ALL_CLAIMS);
        }

        @Test
        void aRuleMayOverrideExtraClaims() {
            var rules = parse("""
                    rules:
                      - match: "org.example:*"
                        requires: a
                        extra-claims: ignore
                      - match: "*"
                        requires: a
                    """).trustPolicySpec().rules();
            assertThat(rules).extracting(RuleSpec::extraClaims)
                    .containsExactly(ClaimSetMode.ANY_CLAIM, null);
        }

        @Test
        void aRuleExtraClaimsValueIsChecked() {
            assertThatThrownBy(() -> parse("rules: [{ match: \"*\", requires: a, extra-claims: allow }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("rules[0]: 'extra-claims' must be 'reject' or 'ignore'");
        }

        @Test
        void extraClaimsIgnoreParsed() {
            assertThat(parse("""
                    defaults: { extra-claims: ignore }
                    rules: [{ match: ["*"], requires: [a] }]
                    """).trustPolicySpec().extraClaims()).isEqualTo(ClaimSetMode.ANY_CLAIM);
        }

        @Test
        void defaultsEnforcementParsed() {
            var doc = parse("""
                    defaults: { on-no-claim: warn }
                    rules: []
                    """).trustPolicySpec();
            assertThat(doc.defaults())
                    .containsEntry(ArtifactOutcome.NO_CLAIM, EnforcementAction.WARN);
        }

        @Test
        void failedEnforcementSettingIsError() {
            assertThatThrownBy(() -> parse("defaults: { on-failed: warn }\nrules: []"))
                    .isInstanceOf(PolicyConfigException.class).hasMessageContaining("FAILED");
        }
    }

    @Nested
    class SigningParsing {

        @Test
        void signingConfig() {
            var config = parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
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
            assertThat(signing.credentialTypes()).isEqualTo(
                    List.of(Credential.TYPE_PGP4, Credential.TYPE_PGP6));
            assertThat(signing.profiles().get("classic")).isEqualTo(List.of(Credential.TYPE_PGP4));
            assertThat(signing.toolchain()).isEqualTo(List.of("sq"));
            assertThat(config.toolsConfig().get("sq").settings().get("cipher-suite")).isEqualTo("mldsa87-ed448");
        }

        @Test
        void sigstoreIsACredentialType() {
            assertThat(parse("signing: { credential-types: [sigstore] }").signingConfig().credentialTypes())
                    .containsExactly(Credential.TYPE_SIGSTORE);
        }

        @Test
        void credentialTypesUseTheSignerKeySpelling() {
            assertThatThrownBy(() -> parse("signing: { credential-types: [openpgp4] }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing: unknown credential type 'openpgp4'")
                    .hasMessageContaining("expected pgp4, pgp6, sigstore");
        }

        @Test
        void aProfileNamingAnUnknownCredentialTypeIsError() {
            assertThatThrownBy(() -> parse("signing: { profiles: { hybrid: [pgp4, pqc] } }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing: unknown credential type 'pqc'")
                    .hasMessageContaining("pgp4, pgp6, sigstore");
        }

        @Test
        void anUnknownSigningKeyIsErrorWithTheNearestKey() {
            assertThatThrownBy(() -> parse("signing: { toolchian: [bc] }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing: unknown key 'toolchian'")
                    .hasMessageContaining("did you mean 'toolchain'?");
        }

        @Test
        void theSignerIsASignerId() {
            assertThatThrownBy(() -> parse("signing: { signer: [alice] }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.signer must be a signer id, not a list");
        }

        @Test
        void aToolchainEntryThatIsNotAToolNameIsError() {
            assertThatThrownBy(() -> parse("signing: { toolchain: [{ bc: true }] }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.toolchain must be a string or a list of strings");
        }

        @Test
        void profilesMapNamesToCredentialTypes() {
            assertThatThrownBy(() -> parse("signing: { profiles: [pgp4] }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.profiles must map profile names to credential types");
        }

        @Test
        void aSigningSectionThatIsNotAMappingIsError() {
            assertThatThrownBy(() -> parse("signing: [bc]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("'signing' must be a mapping, not a list");
        }

        @Test
        void noSigningSection() {
            var config = parse("");
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
            var dc = config.verificationConfig();
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
            assertThat(config.verificationConfig().toolchain()).isEqualTo(List.of("sq", "gpg"));
        }

        @Test
        void toolchainScalar() {
            var config = parse("""
                    verification:
                      toolchain: gpg
                    """);
            assertThat(config.verificationConfig().toolchain()).isEqualTo(List.of("gpg"));
        }

        @Test
        void toolchainDefault() {
            var config = parse("""
                    verification:
                      resolve-signers: true
                    """);
            assertThat(config.verificationConfig().toolchain()).isNull();
            assertThat(config.verificationConfig().effectiveToolchain()).isEqualTo(VerificationConfig.DEFAULT_TOOL_PRIORITY);
        }

        @Test
        void anUnknownVerificationKeyIsErrorWithTheNearestKey() {
            assertThatThrownBy(() -> parse("verification: { resolve-signer: false }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("verification: unknown key 'resolve-signer'")
                    .hasMessageContaining("did you mean 'resolve-signers'?");
        }

        /**
         * A flag that is not a boolean used to read as {@code false}, so {@code "off"} and
         * {@code "true"} alike turned key fetching off.
         */
        @Test
        void aFlagThatIsNotABooleanIsErrorRatherThanFalse() {
            assertThatThrownBy(() -> parse("verification: { resolve-signers: \"true\" }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("verification.resolve-signers must be true or false");
        }

        /** In YAML 1.2 {@code yes} and {@code on} are words, not booleans. */
        @Test
        void yesIsNotTrue() {
            assertThatThrownBy(() -> parse("verification: { resolve-signers: yes }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("verification.resolve-signers must be true or false, not 'yes'");
        }

        @Test
        void keyserversThatAreAMappingAreErrorRatherThanEmpty() {
            assertThatThrownBy(() -> parse("verification: { keyservers: { url: hkps://keys.openpgp.org } }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("verification.keyservers must be a string or a list of strings");
        }

        @Test
        void noVerificationSection() {
            var config = parse("");
            assertThat(config.verificationConfig()).isEqualTo(VerificationConfig.DEFAULT);
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
        void aToolMapsToItsSettings() {
            assertThatThrownBy(() -> parse("tools: { bc: [gnupg-home] }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools.bc must be a mapping of settings, not a list");
        }

        @Test
        void aSettingWrittenAsAListIsJoinedAndRecorded() {
            ToolConfig sq = parse("tools: { sq: { signing-fingerprint: [A, B] } }").toolsConfig().get("sq");

            assertThat(sq.settings()).containsEntry("signing-fingerprint", "A,B");
            assertThat(sq.lists()).containsExactly("signing-fingerprint");
        }

        @Test
        void aListItemThatIsAMappingIsError() {
            assertThatThrownBy(() -> parse("tools: { sq: { signing-fingerprint: [{ a: b }] } }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining(
                            "tools.sq.signing-fingerprint: list items must be single values, not a mapping");
        }

        /**
         * The file is read as YAML 1.2, as editors read it: an unquoted {@code 0x…} value or a
         * number with a leading zero stays as written. Read as YAML 1.1, {@code 0x12345678}
         * reached gpg as {@code 305419896}, and {@code 0123} as the octal {@code 83}.
         */
        @Test
        void anUnquotedHexOrLeadingZeroValueStaysAsWritten() {
            var settings = parse("tools: { gpg: { passphrase-env: 0x12345678, executable: 0123 } }")
                    .toolsConfig().get("gpg").settings();

            assertThat(settings).containsEntry("passphrase-env", "0x12345678").containsEntry("executable", "0123");
        }

        @Test
        void aToolWithNoSettingsIsAllowed() {
            assertThat(parse("tools: { sq: }").toolsConfig().get("sq").settings()).isEmpty();
        }

        @Test
        void noToolsSection() {
            var config = parse("");
            assertThat(config.toolsConfig().isEmpty()).isTrue();
        }
    }

    @Nested
    class ArtifactSetsParsing {

        @Test
        void aSetMemberThatIsNotAPatternIsError() {
            assertThatThrownBy(() -> parse("artifact-sets: { stack: [{ group: org.apache }] }"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("artifact-sets.stack must be a string or a list of strings");
        }
    }

    @Nested
    class SchemaMigration {

        @Test
        void oldTrustSchemaRejectedWithGuidance() {
            assertThatThrownBy(() -> parse("trust: { \"org.acme:*\": alice }"))
                    .isInstanceOf(PolicyConfigException.class).hasMessageContaining("rules");
        }

        @Test
        void oldArtifactsKeyRejectedWithGuidance() {
            assertThatThrownBy(() -> parse("artifacts: { g: [\"com.acme.*\"] }"))
                    .isInstanceOf(PolicyConfigException.class).hasMessageContaining("artifact-sets");
        }

        @Test
        void oldSignatureOptionalRejectedWithGuidance() {
            assertThatThrownBy(() -> parse("signature-optional: true"))
                    .isInstanceOf(PolicyConfigException.class).hasMessageContaining("rules");
        }

        @Test
        void versionKeyRejectedWithGuidance() {
            assertThatThrownBy(() -> parse("version: 2"))
                    .isInstanceOf(PolicyConfigException.class).hasMessageContaining("remove it");
        }

        @Test
        void oldPolicyKeyRejectedWithGuidance() {
            assertThatThrownBy(() -> parse("policy: { enforce: true }"))
                    .isInstanceOf(PolicyConfigException.class).hasMessageContaining("rules");
        }
    }

    @Nested
    class TopLevelKeys {

        @Test
        void unknownTopLevelKeyIsErrorSuggestingTheNearestKey() {
            assertThatThrownBy(() -> parse("rule: [{ match: [\"*\"], requires: [a] }]"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("'rule'")
                    .hasMessageContaining("did you mean 'rules'");
        }

        @Test
        void unknownTopLevelKeyFarFromAnyKnownKeyListsTheKnownKeys() {
            assertThatThrownBy(() -> parse("frobnicate: true"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("'frobnicate'")
                    .hasMessageContaining("artifact-sets");
        }

        @Test
        void emptyDocumentIsZeroConfig() {
            assertThat(parse("").trustPolicySpec().declared()).isFalse();
        }
    }

    @Nested
    class SigningSigner {

        private static final String SIGNERS = """
                signers:
                  alice:
                    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                """;

        @Test
        void aSignerTheFileDoesNotDefineIsALoadError() {
            String yaml = SIGNERS + """
                    signing:
                      signer: alcie
                    """;
            assertThatThrownBy(() -> SigmundConfigParser.parse("test", new StringReader(yaml)))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.signer")
                    .hasMessageContaining("'alcie'")
                    .hasMessageContaining("did you mean 'alice'?");
        }

        @Test
        void aDefinedSignerLoads() throws Exception {
            String yaml = SIGNERS + """
                    signing:
                      signer: alice
                    """;
            SigmundConfig config = SigmundConfigParser.parse("test", new StringReader(yaml));
            assertThat(config.signingConfig().signer()).isEqualTo("alice");
        }

        @Test
        void anAddressNoListedIssuerCanVouchForIsALoadError() {
            String yaml = """
                    signers:
                      alice:
                        email: "alice@example.com"
                    signing:
                      signer: alice
                    """;
            assertThatThrownBy(() -> parse(yaml))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.signer")
                    .hasMessageContaining("'alice'")
                    .hasMessageContaining("{email=alice@example.com}")
                    .hasMessageContaining("add one to 'issuers'");
        }

        @Test
        void anAddressAListedIssuerVouchesForLoads() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: "alice@example.com"
                    signing:
                      signer: alice
                    """);
            assertThat(config.signingConfig().signer()).isEqualTo("alice");
        }

        @Test
        void aMisspelledAttributeOfTheSignerIsALoadError() {
            String yaml = """
                    signers:
                      ci:
                        identities:
                          - issuer: "https://token.actions.githubusercontent.com"
                            source-repository-url: "https://github.com/acme/app"
                    signing:
                      signer: ci
                    """;
            assertThatThrownBy(() -> parse(yaml))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.signer")
                    .hasMessageContaining("source-repository-url=https://github.com/acme/app")
                    .hasMessageContaining("did you mean 'source-repository-uri'?");
        }

        @Test
        void anAttributeTheEntrysIssuerCannotAssertIsALoadError() {
            String yaml = """
                    signers:
                      alice:
                        identities:
                          - issuer: keys.openpgp.org
                            subject: "alice@example.com"
                    signing:
                      signer: alice
                    """;
            assertThatThrownBy(() -> parse(yaml))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.signer")
                    .hasMessageContaining("cannot assert subject");
        }

        @Test
        void anUnclassifiableIssuerOfTheSignerIsALoadError() {
            String yaml = """
                    signers:
                      alice:
                        identities:
                          - issuer: "http://issuer.example.com"
                            subject: "alice@example.com"
                    signing:
                      signer: alice
                    """;
            assertThatThrownBy(() -> parse(yaml))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.signer")
                    .hasMessageContaining("http://issuer.example.com");
        }

        @Test
        void aMembersEntryIsValidatedToo() {
            String yaml = """
                    signers:
                      team:
                        members:
                          - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            email: "dev@example.com"
                    signing:
                      signer: team
                    """;
            assertThatThrownBy(() -> parse(yaml))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.signer")
                    .hasMessageContaining("{email=dev@example.com}");
        }

        /**
         * Only the asserted signer is checked: signing never compiles the policy, so an entry of
         * another signer that verification would reject does not stop the file loading.
         */
        @Test
        void otherSignersAreLeftToThePolicyCompile() {
            var config = parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                      bob:
                        email: "bob@example.com"
                    signing:
                      signer: alice
                    """);
            assertThat(config.signingConfig().signer()).isEqualTo("alice");
        }
    }

    @Nested
    class FullConfig {

        @Test
        void parsesCompleteConfig() {
            var config = parse("""
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23000000000000000000000000"
                        pgp6: "ABCD1234ABCD1234000000000000000000000000000000000000000000000000"
                      bob: "bob@example.com"
                    artifact-sets:
                      example-stack: ["org.example.*"]
                    signing:
                      signer: alice
                    rules:
                      - match: ["org.example:*"]
                        requires: [alice, bob]
                      - match: ["*"]
                        on-no-claim: ignore
                    defaults:
                      extra-claims: ignore
                    verification:
                      resolve-signers: true
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            assertThat(config.signers().names().size()).isEqualTo(2);
            assertThat(config.signingConfig().signer()).isEqualTo("alice");
            assertThat(config.trustPolicySpec().rules()).hasSize(2);
            assertThat(config.trustPolicySpec().extraClaims()).isEqualTo(ClaimSetMode.ANY_CLAIM);
            assertThat(config.trustPolicySpec().declared()).isTrue();
            assertThat(config.verificationConfig().resolveSigners()).isTrue();

            TrustPolicy policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
            assertThat(policy.matchRule(artifact("org.example", "lib", "1.0")).requirement()
                    .clauses()).hasSize(2);
        }
    }

    private static ArtifactCoords artifact(String ns, String name, String version) {
        return new ArtifactCoords(ns, name, "", "jar", version);
    }
}
