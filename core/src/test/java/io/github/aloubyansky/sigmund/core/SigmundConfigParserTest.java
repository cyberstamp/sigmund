package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.StringReader;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SigmundConfigParserTest {

    private SigmundConfig parse(String yaml) {
        return SigmundConfigParser.parse(new StringReader(yaml));
    }

    @Nested
    class SignerParsing {

        @Test
        void minimalSigner_emailString() {
            var config = parse("""
                    signers:
                      bob: "bob@example.com"
                    """);
            var bob = config.signers().get("bob");
            assertNotNull(bob);
            assertNull(bob.displayName());
            assertEquals(1, bob.credentials().size());
            assertInstanceOf(EmailCredential.class, bob.credentials().get(0));
            assertEquals("bob@example.com", ((EmailCredential) bob.credentials().get(0)).email());
        }

        @Test
        void objectSigner_withFingerprints() {
            var config = parse("""
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        openpgp4: "4AEE18F83AFDEB23"
                        openpgp6: "ABCD1234ABCD1234"
                    """);
            var alice = config.signers().get("alice");
            assertEquals("Alice", alice.displayName());
            assertEquals(3, alice.credentials().size());

            var types = alice.credentials().stream().map(Credential::type).toList();
            assertTrue(types.contains("openpgp4"));
            assertTrue(types.contains("openpgp6"));
            assertTrue(types.contains("email"));
        }

        @Test
        void objectSigner_withOidc() {
            var config = parse("""
                    signers:
                      ci-pipeline:
                        name: "CI Pipeline"
                        oidc:
                          issuer: "https://token.actions.githubusercontent.com"
                          subject: "https://github.com/org/repo"
                    """);
            var ci = config.signers().get("ci-pipeline");
            assertEquals("CI Pipeline", ci.displayName());
            assertEquals(1, ci.credentials().size());
            var oidc = assertInstanceOf(OidcCredential.class, ci.credentials().get(0));
            assertEquals("https://token.actions.githubusercontent.com", oidc.issuer());
            assertEquals("https://github.com/org/repo", oidc.subject());
        }

        @Test
        void pgp4Alias() {
            var config = parse("""
                    signers:
                      alice:
                        pgp4: "4AEE18F83AFDEB23"
                    """);
            var alice = config.signers().get("alice");
            var fp = assertInstanceOf(FingerprintCredential.class, alice.credentials().get(0));
            assertEquals("openpgp4", fp.type());
        }

        @Test
        void pgp6Alias() {
            var config = parse("""
                    signers:
                      alice:
                        pgp6: "ABCD1234ABCD1234"
                    """);
            var fp = assertInstanceOf(FingerprintCredential.class,
                    config.signers().get("alice").credentials().get(0));
            assertEquals("openpgp6", fp.type());
        }

        @Test
        void objectSigner_withEmailAndFingerprint() {
            var config = parse("""
                    signers:
                      alice:
                        name: "Alice"
                        email: "alice@example.com"
                        pgp4: "4AEE18F83AFDEB23"
                    """);
            var alice = config.signers().get("alice");
            assertEquals("Alice", alice.displayName());
            assertTrue(alice.credentials().stream()
                    .anyMatch(c -> c instanceof EmailCredential ec && ec.email().equals("alice@example.com")));
        }
    }

    @Nested
    class TrustParsing {

        @Test
        void trustMappings_resolved() {
            var config = parse("""
                    signers:
                      alice:
                        openpgp4: "4AEE18F83AFDEB23"
                    trust:
                      "org.example:*": [alice]
                    """);
            var artifact = artifact("org.example", "lib", "1.0");
            var expected = config.trustPolicy().expectedSigners(artifact);
            assertEquals(1, expected.size());
            assertEquals("alice", expected.get(0).id());
        }

        @Test
        void trustMappings_singleString() {
            var config = parse("""
                    signers:
                      bob: "bob@example.com"
                    trust:
                      "org.example:lib": bob
                    """);
            var expected = config.trustPolicy().expectedSigners(artifact("org.example", "lib", "1.0"));
            assertEquals(1, expected.size());
            assertEquals("bob", expected.get(0).id());
        }

        @Test
        void trustMappings_undefinedSigner_throws() {
            assertThrows(PolicyConfigException.class, () -> parse("""
                    trust:
                      "org.example:*": [nonexistent]
                    """));
        }

        @Test
        void unsignedAllowed() {
            var config = parse("""
                    unsigned:
                      - "org.example:unsigned-lib"
                    """);
            assertTrue(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "unsigned-lib", "1.0")));
            assertFalse(config.trustPolicy().isUnsignedAllowed(
                    artifact("org.example", "other-lib", "1.0")));
        }
    }

    @Nested
    class PolicyParsing {

        @Test
        void defaults() {
            var config = parse("version: 1");
            assertTrue(config.trustPolicy().requireAllEvidenceMatch());
            assertEquals(UntrustedPolicy.FAIL, config.trustPolicy().onUntrusted());
        }

        @Test
        void warnPolicy() {
            var config = parse("""
                    policy:
                      on-untrusted: warn
                      require-all-evidence-match: false
                    """);
            assertEquals(UntrustedPolicy.WARN, config.trustPolicy().onUntrusted());
            assertFalse(config.trustPolicy().requireAllEvidenceMatch());
        }

        @Test
        void invalidPolicy_throws() {
            assertThrows(PolicyConfigException.class, () -> parse("""
                    policy:
                      on-untrusted: ignore
                    """));
        }
    }

    @Nested
    class SigningParsing {

        @Test
        void signingConfig() {
            var config = parse("""
                    signing:
                      signer: alice
                      default-profile: hybrid
                      profiles:
                        hybrid: [openpgp4, openpgp6]
                      tools:
                        sq:
                          cipher-suite: "mldsa87-ed448"
                    """);
            var signing = config.signingConfig();
            assertEquals("alice", signing.signer());
            assertEquals("hybrid", signing.defaultProfile());
            assertEquals(List.of("openpgp4", "openpgp6"), signing.profiles().get("hybrid"));
            assertEquals("mldsa87-ed448", signing.tools().get("sq").settings().get("cipher-suite"));
        }

        @Test
        void noSigningSection() {
            var config = parse("version: 1");
            assertEquals(SigningConfig.DEFAULT, config.signingConfig());
        }
    }

    @Nested
    class DiscoveryParsing {

        @Test
        void discoveryConfig() {
            var config = parse("""
                    discovery:
                      fetch-signer-info: true
                      import-to-keyring: false
                      keyservers:
                        - "hkps://keys.openpgp.org"
                      tools:
                        sigstore:
                          trusted-root: "/path/to/root.json"
                    """);
            var dc = config.discoveryConfig();
            assertTrue(dc.fetchSignerInfo());
            assertFalse(dc.importToKeyring());
            assertEquals(List.of("hkps://keys.openpgp.org"), dc.keyservers());
            assertEquals("/path/to/root.json", dc.tools().get("sigstore").get("trusted-root"));
        }

        @Test
        void noDiscoverySection() {
            var config = parse("version: 1");
            assertEquals(DiscoveryConfig.DEFAULT, config.discoveryConfig());
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
                        openpgp4: "4AEE18F83AFDEB23"
                        openpgp6: "ABCD1234ABCD1234"
                      bob: "bob@example.com"
                    signing:
                      signer: alice
                    trust:
                      "org.example:*": [alice, bob]
                    unsigned:
                      - "org.example:unsigned-lib"
                    policy:
                      on-untrusted: fail
                      require-all-evidence-match: true
                    discovery:
                      fetch-signer-info: true
                      keyservers:
                        - "hkps://keys.openpgp.org"
                    """);
            assertEquals(1, config.version());
            assertEquals(2, config.signers().size());
            assertEquals("alice", config.signingConfig().signer());
            assertTrue(config.trustPolicy().requireAllEvidenceMatch());
            assertTrue(config.discoveryConfig().fetchSignerInfo());
        }
    }

    private static ArtifactIdentity artifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            @Override
            public String namespace() {
                return ns;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String version() {
                return version;
            }
        };
    }
}
