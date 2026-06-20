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
                      alice: "Alice <alice@example.com>"
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
                      alice: "Alice <alice@example.com>"
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
                      alice: "Alice <alice@example.com>"
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
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example: alice
                    """);
            var signer = config.signers().get("alice");
            assertNotNull(signer);
            assertNull(signer.name());
            assertEquals(1, signer.members().size());
            var member = signer.members().get(0);
            assertNull(member.gpg());
            assertNull(member.pqc());
            assertEquals("Alice <alice@example.com>", member.uid());
        }

        @Test
        void shortFormGpgAndUid() throws IOException {
            var config = parse("""
                    signers:
                      jane:
                        gpg: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                        uid: "Jane Doe <jane@example.com>"
                    trust:
                      com.example: jane
                    """);
            var signer = config.signers().get("jane");
            assertNotNull(signer);
            assertNull(signer.name());
            assertEquals(1, signer.members().size());
            var member = signer.members().get(0);
            assertEquals("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", member.gpg());
            assertEquals("Jane Doe <jane@example.com>", member.uid());
            assertNull(member.pqc());
        }

        @Test
        void shortFormPqcOnly() throws IOException {
            var config = parse("""
                    signers:
                      pqc-signer:
                        pqc: "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0"
                    trust:
                      com.example: pqc-signer
                    """);
            var member = config.signers().get("pqc-signer").members().get(0);
            assertNull(member.gpg());
            assertEquals("A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0", member.pqc());
            assertNull(member.uid());
        }

        @Test
        void shortFormUidOnly() throws IOException {
            var config = parse("""
                    signers:
                      guava-team:
                        uid: "Google Inc <opensource@google.com>"
                    trust:
                      com.google.guava: guava-team
                    """);
            var member = config.signers().get("guava-team").members().get(0);
            assertNull(member.gpg());
            assertNull(member.pqc());
            assertEquals("Google Inc <opensource@google.com>", member.uid());
        }

        @Test
        void fullFormWithNameAndMembers() throws IOException {
            var config = parse("""
                    signers:
                      apache:
                        name: "Apache Software Foundation"
                        members:
                          - gpg: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            uid: "Maven PMC <dev@maven.apache.org>"
                          - gpg: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                    trust:
                      org.apache.*: apache
                    """);
            var signer = config.signers().get("apache");
            assertEquals("Apache Software Foundation", signer.name());
            assertEquals(2, signer.members().size());

            var m0 = signer.members().get(0);
            assertEquals("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", m0.gpg());
            assertEquals("Maven PMC <dev@maven.apache.org>", m0.uid());

            var m1 = signer.members().get(1);
            assertEquals("BBE7232D7991050B54C8EA0ADC08637CA615D22C", m1.gpg());
            assertNull(m1.uid());
        }

        @Test
        void fullFormWithoutName() throws IOException {
            var config = parse("""
                    signers:
                      team:
                        members:
                          - uid: "Dev A <a@example.com>"
                          - uid: "Dev B <b@example.com>"
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
                      apache: "Apache <dev@apache.org>"
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
                      alice: "Alice <alice@example.com>"
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
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example: alice
                    """);
            assertEquals(List.of("alice"), config.trust().get("com.example"));
        }

        @Test
        void multipleSignerRefs() throws IOException {
            var config = parse("""
                    signers:
                      redhat: "Red Hat <signing@redhat.com>"
                      jboss: "JBoss <dev@jboss.org>"
                    trust:
                      io.quarkus.*: [redhat, jboss]
                    """);
            assertEquals(List.of("redhat", "jboss"), config.trust().get("io.quarkus.*"));
        }

        @Test
        void unknownSignerRefThrows() {
            var ex = assertThrows(IllegalArgumentException.class, () -> parse("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example: unknown
                    """));
            assertTrue(ex.getMessage().contains("unknown signer 'unknown'"));
        }

        @Test
        void multipleEntriesPreserved() throws IOException {
            var config = parse("""
                    signers:
                      alice: "Alice <alice@example.com>"
                      bob: "Bob <bob@example.com>"
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
                      alice: "Alice <alice@example.com>"
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
                      alice: "Alice <alice@example.com>"
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
                          - gpg: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                            uid: "Maven PMC <dev@maven.apache.org>"
                          - gpg: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
                      jane:
                        gpg: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
                        uid: "Jane Doe <jane@example.com>"
                      jackson-dev: "Tatu Saloranta <tatu@fasterxml.com>"

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
                    jane.members().get(0).gpg());

            var jackson = config.signers().get("jackson-dev");
            assertEquals("Tatu Saloranta <tatu@fasterxml.com>",
                    jackson.members().get(0).uid());
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
                        gpg: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                        pqc: "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0"
                        uid: "Full Signer <full@example.com>"
                    trust:
                      com.example: full
                    """);
            var member = config.signers().get("full").members().get(0);
            assertNotNull(member.gpg());
            assertNotNull(member.pqc());
            assertNotNull(member.uid());
        }

        @Test
        void trustWithArraySyntaxExpanded() throws IOException {
            var config = parse("""
                    signers:
                      a: "A <a@example.com>"
                      b: "B <b@example.com>"
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
