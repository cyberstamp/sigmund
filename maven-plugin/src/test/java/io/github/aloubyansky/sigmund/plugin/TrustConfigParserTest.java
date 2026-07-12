package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TrustConfigParserTest {

    // ── Settings ────────────────────────────────────────────

    @Nested
    class SettingsTests {

        @Test
        void defaultsWhenOmitted() throws IOException {
            var config = parse("""
                    trust:
                      com.example: alice
                    signers:
                      alice: "alice@example.com"
                    """);
            var s = config.settings();
            assertEquals(List.of(), s.keyservers());
            assertEquals("fail", s.onUntrusted());
            assertTrue(s.verifyAllSignatures());
            assertTrue(s.fetchSignerInfo());
        }

        @Test
        void explicitSettings() throws IOException {
            var config = parse("""
                    settings:
                      keyservers:
                        - hkps://keys.openpgp.org
                        - hkps://keyserver.ubuntu.com
                      on-untrusted: warn
                      verify-all-signatures: false
                      fetch-signer-info: false
                    trust:
                      com.example: alice
                    signers:
                      alice: "alice@example.com"
                    """);
            var s = config.settings();
            assertEquals(List.of("hkps://keys.openpgp.org", "hkps://keyserver.ubuntu.com"),
                    s.keyservers());
            assertEquals("warn", s.onUntrusted());
            assertFalse(s.verifyAllSignatures());
            assertFalse(s.fetchSignerInfo());
        }

        @Test
        void invalidOnUntrustedThrows() {
            var ex = assertThrows(IllegalArgumentException.class, () -> parse("""
                    settings:
                      on-untrusted: explode
                    trust:
                      com.example: alice
                    signers:
                      alice: "alice@example.com"
                    """));
            assertTrue(ex.getMessage().contains("on-untrusted"));
        }
    }

    // ── Signers ─────────────────────────────────────────────

    @Nested
    class SignerTests {

        @Test
        void minimalForm() throws IOException {
            var config = parse("""
                    signers:
                      alice: "alice@example.com"
                    trust:
                      com.example: alice
                    """);
            var signer = config.signers().get("alice");
            assertNotNull(signer);
            assertNull(signer.name());
            assertEquals(1, signer.members().size());
            var member = signer.members().get(0);
            assertNull(member.pgp4());
            assertNull(member.pgp6());
            assertEquals("alice@example.com", member.email());
        }

        @Test
        void shortFormGpgAndEmail() throws IOException {
            var config = parse("""
                    signers:
                      jane:
                        pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                        email: "jane@example.com"
                    trust:
                      com.example: jane
                    """);
            var signer = config.signers().get("jane");
            assertNotNull(signer);
            assertNull(signer.name());
            assertEquals(1, signer.members().size());
            var member = signer.members().get(0);
            assertEquals("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", member.pgp4());
            assertEquals("jane@example.com", member.email());
            assertNull(member.pgp6());
        }

        @Test
        void shortFormPqcOnly() throws IOException {
            var config = parse("""
                    signers:
                      pqc-signer:
                        pgp6: "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0"
                    trust:
                      com.example: pqc-signer
                    """);
            var member = config.signers().get("pqc-signer").members().get(0);
            assertNull(member.pgp4());
            assertEquals("A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0", member.pgp6());
            assertNull(member.email());
        }

        @Test
        void shortFormEmailOnly() throws IOException {
            var config = parse("""
                    signers:
                      guava-team:
                        email: "opensource@google.com"
                    trust:
                      com.google.guava: guava-team
                    """);
            var member = config.signers().get("guava-team").members().get(0);
            assertNull(member.pgp4());
            assertNull(member.pgp6());
            assertEquals("opensource@google.com", member.email());
        }

        @Test
        void fullFormWithNameAndMembers() throws IOException {
            var config = parse("""
                    signers:
                      apache:
                        name: "Apache Software Foundation"
                        members:
                          - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            email: "dev@maven.apache.org"
                          - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    trust:
                      org.apache.*: apache
                    """);
            var signer = config.signers().get("apache");
            assertEquals("Apache Software Foundation", signer.name());
            assertEquals(2, signer.members().size());

            var m0 = signer.members().get(0);
            assertEquals("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", m0.pgp4());
            assertEquals("dev@maven.apache.org", m0.email());

            var m1 = signer.members().get(1);
            assertEquals("BBE7232D7991050B54C8EA0ADC08637CA615D22C", m1.pgp4());
            assertNull(m1.email());
        }

        @Test
        void fullFormWithoutName() throws IOException {
            var config = parse("""
                    signers:
                      team:
                        members:
                          - email: "a@example.com"
                          - email: "b@example.com"
                    trust:
                      com.example: team
                    """);
            var signer = config.signers().get("team");
            assertNull(signer.name());
            assertEquals(2, signer.members().size());
        }

        @Test
        void memberWithNoCredentialThrows() {
            assertThrows(IllegalArgumentException.class, () -> parse("""
                    signers:
                      bad:
                        members:
                          - {}
                    trust:
                      com.example: bad
                    """));
        }

        @Test
        void emptyMembersArrayThrows() {
            assertThrows(IllegalArgumentException.class, () -> parse("""
                    signers:
                      bad:
                        members: []
                    trust:
                      com.example: bad
                    """));
        }
    }

    // ── Artifacts ────────────────────────────────────────────

    @Nested
    class ArtifactTests {

        @Test
        void artifactGroupsDefined() throws IOException {
            var config = parse("""
                    signers:
                      apache: "dev@apache.org"
                    artifacts:
                      apache-stack:
                        - org.apache.maven.*
                        - org.apache.commons.*
                    trust:
                      apache-stack: apache
                    """);
            assertEquals(Map.of("apache-stack",
                    List.of("org.apache.maven.*", "org.apache.commons.*")),
                    config.artifacts());
        }

        @Test
        void noArtifactsSection() throws IOException {
            var config = parse("""
                    signers:
                      alice: "alice@example.com"
                    trust:
                      com.example: alice
                    """);
            assertTrue(config.artifacts().isEmpty());
        }
    }

    // ── Trust ───────────────────────────────────────────────

    @Nested
    class TrustTests {

        @Test
        void singleSignerRef() throws IOException {
            var config = parse("""
                    signers:
                      alice: "alice@example.com"
                    trust:
                      com.example: alice
                    """);
            assertEquals(List.of("alice"), config.trust().get("com.example"));
        }

        @Test
        void multipleSignerRefs() throws IOException {
            var config = parse("""
                    signers:
                      redhat: "signing@redhat.com"
                      jboss: "dev@jboss.org"
                    trust:
                      io.quarkus.*: [redhat, jboss]
                    """);
            assertEquals(List.of("redhat", "jboss"), config.trust().get("io.quarkus.*"));
        }

        @Test
        void unknownSignerRefThrows() {
            var ex = assertThrows(IllegalArgumentException.class, () -> parse("""
                    signers:
                      alice: "alice@example.com"
                    trust:
                      com.example: unknown
                    """));
            assertTrue(ex.getMessage().contains("unknown signer 'unknown'"));
        }

        @Test
        void multipleEntriesPreserved() throws IOException {
            var config = parse("""
                    signers:
                      alice: "alice@example.com"
                      bob: "bob@example.com"
                    trust:
                      com.example: alice
                      com.other.*: bob
                    """);
            assertEquals(2, config.trust().size());
            assertEquals(List.of("alice"), config.trust().get("com.example"));
            assertEquals(List.of("bob"), config.trust().get("com.other.*"));
        }
    }

    // ── Unsigned ─────────────────────────────────────────────

    @Nested
    class UnsignedTests {

        @Test
        void unsignedPatterns() throws IOException {
            var config = parse("""
                    signers:
                      alice: "alice@example.com"
                    trust:
                      com.example: alice
                    unsigned:
                      - com.internal.*
                      - org.example:test-utils
                    """);
            assertEquals(List.of("com.internal.*", "org.example:test-utils"),
                    config.unsigned());
        }

        @Test
        void noUnsignedSection() throws IOException {
            var config = parse("""
                    signers:
                      alice: "alice@example.com"
                    trust:
                      com.example: alice
                    """);
            assertTrue(config.unsigned().isEmpty());
        }
    }

    // ── Full config ─────────────────────────────────────────

    @Nested
    class FullConfigTests {

        @Test
        void completeConfig() throws IOException {
            var config = parse("""
                    settings:
                      keyservers:
                        - hkps://keys.openpgp.org
                      on-untrusted: fail
                      verify-all-signatures: true
                      fetch-signer-info: true

                    signers:
                      apache:
                        name: "Apache Software Foundation"
                        members:
                          - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            email: "dev@maven.apache.org"
                          - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                      jane:
                        pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
                        email: "jane@example.com"
                      jackson-dev: "tatu@fasterxml.com"

                    artifacts:
                      apache-stack:
                        - org.apache.maven.*
                        - org.apache.commons.*

                    trust:
                      apache-stack: apache
                      com.fasterxml.jackson.*: jackson-dev
                      com.example:lib: jane

                    unsigned:
                      - com.internal.*
                    """);

            assertEquals(3, config.signers().size());
            assertEquals(1, config.artifacts().size());
            assertEquals(3, config.trust().size());
            assertEquals(1, config.unsigned().size());

            var apache = config.signers().get("apache");
            assertEquals("Apache Software Foundation", apache.name());
            assertEquals(2, apache.members().size());

            var jane = config.signers().get("jane");
            assertNull(jane.name());
            assertEquals(1, jane.members().size());
            assertEquals("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
                    jane.members().get(0).pgp4());

            var jackson = config.signers().get("jackson-dev");
            assertEquals("tatu@fasterxml.com",
                    jackson.members().get(0).email());
        }
    }

    // ── Edge cases ──────────────────────────────────────────

    @Nested
    class EdgeCaseTests {

        @Test
        void emptySignersSection() throws IOException {
            var config = parse("""
                    signers:
                    trust:
                    """);
            assertTrue(config.signers().isEmpty());
            assertTrue(config.trust().isEmpty());
        }

        @Test
        void memberWithAllThreeFields() throws IOException {
            var config = parse("""
                    signers:
                      full:
                        pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                        pgp6: "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0"
                        email: "full@example.com"
                    trust:
                      com.example: full
                    """);
            var member = config.signers().get("full").members().get(0);
            assertNotNull(member.pgp4());
            assertNotNull(member.pgp6());
            assertNotNull(member.email());
        }

        @Test
        void trustWithArraySyntaxExpanded() throws IOException {
            var config = parse("""
                    signers:
                      a: "a@example.com"
                      b: "b@example.com"
                    trust:
                      com.example:
                        - a
                        - b
                    """);
            assertEquals(List.of("a", "b"), config.trust().get("com.example"));
        }
    }

    private TrustConfig parse(String yaml) throws IOException {
        return TrustConfigParser.parse(new StringReader(yaml));
    }
}
