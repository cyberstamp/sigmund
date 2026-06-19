package io.github.aloubyansky.pqc.maven.plugin;

import static org.junit.jupiter.api.Assertions.*;

import io.github.aloubyansky.pqc.maven.core.SignatureInfo;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyMojoTest {

    @Nested
    class VerificationStateTests {

        private TrustConfig configWithSigner(String ref, String uid) {
            var member = new TrustConfig.Member(null, null, uid);
            var signer = new TrustConfig.Signer(null, List.of(member));
            return new TrustConfig(
                    TrustConfig.Settings.defaults(),
                    Map.of(ref, signer),
                    Map.of(),
                    Map.of(),
                    List.of());
        }

        @Test
        void isUidTrustedReturnsTrueForTrustedSignerUid() {
            var state = new VerifyMojo.VerificationState(
                    true, false, configWithSigner("alice", "Alice <alice@example.com>"));
            state.allTrustedSignerRefs.add("alice");
            assertTrue(state.isUidTrusted("Alice <alice@example.com>"));
        }

        @Test
        void isUidTrustedReturnsFalseForUnknownUid() {
            var state = new VerifyMojo.VerificationState(
                    true, false, configWithSigner("alice", "Alice <alice@example.com>"));
            state.allTrustedSignerRefs.add("alice");
            assertFalse(state.isUidTrusted("Bob <bob@example.com>"));
        }

        @Test
        void isUidTrustedReturnsFalseWhenRefNotInTrustedSet() {
            var state = new VerifyMojo.VerificationState(
                    true, false, configWithSigner("alice", "Alice <alice@example.com>"));
            assertFalse(state.isUidTrusted("Alice <alice@example.com>"));
        }
    }

    @Nested
    class FingerprintMatchTests {

        @Test
        void exactMatch() {
            assertTrue(VerifyMojo.fingerprintsMatch(
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"));
        }

        @Test
        void suffixMatchExpectedLonger() {
            assertTrue(VerifyMojo.fingerprintsMatch(
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "2D7BAF3C1E9F5A12"));
        }

        @Test
        void suffixMatchActualLonger() {
            assertTrue(VerifyMojo.fingerprintsMatch(
                    "2D7BAF3C1E9F5A12",
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"));
        }

        @Test
        void caseInsensitive() {
            assertTrue(VerifyMojo.fingerprintsMatch(
                    "4aee18f83afdeb23468b2e5a2d7baf3c1e9f5a12",
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"));
        }

        @Test
        void tooShortRejected() {
            assertFalse(VerifyMojo.fingerprintsMatch(
                    "1E9F5A12",
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"));
        }

        @Test
        void noMatch() {
            assertFalse(VerifyMojo.fingerprintsMatch(
                    "AAAAAAAAAAAAAAAA",
                    "BBBBBBBBBBBBBBBB"));
        }
    }

    @Nested
    class MemberMatchTests {

        @Test
        void gpgFingerprintMatch() {
            var member = new TrustConfig.Member(
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", null, null);
            var sig = new SignatureInfo(4,
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertTrue(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void gpgFingerprintSuffixMatch() {
            var member = new TrustConfig.Member(
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", null, null);
            var sig = new SignatureInfo(4,
                    "2D7BAF3C1E9F5A12",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertTrue(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void gpgFingerprintNoMatch() {
            var member = new TrustConfig.Member(
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", null, null);
            var sig = new SignatureInfo(4,
                    "BBBBBBBBBBBBBBBB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void pqcFingerprintMatchV6() {
            var member = new TrustConfig.Member(null,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991", null);
            var sig = new SignatureInfo(6,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991",
                    "ML-DSA", null, VerificationResult.PASS);
            assertTrue(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void pqcFingerprintIgnoredForV4() {
            var member = new TrustConfig.Member(null,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991", null);
            var sig = new SignatureInfo(4,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991",
                    "RSA", null, VerificationResult.PASS);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void uidMatch() {
            var member = new TrustConfig.Member(null, null, "Alice <alice@example.com>");
            var sig = new SignatureInfo(4, "KEYID1234567890AB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertTrue(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void uidNoMatch() {
            var member = new TrustConfig.Member(null, null, "Alice <alice@example.com>");
            var sig = new SignatureInfo(4, "KEYID1234567890AB",
                    "RSA", "Bob <bob@example.com>", VerificationResult.PASS);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void gpgTakesPrecedenceOverUid() {
            var member = new TrustConfig.Member(
                    "AAAAAAAAAAAAAAAA", null, "Alice <alice@example.com>");
            var sig = new SignatureInfo(4, "BBBBBBBBBBBBBBBB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            // GPG fingerprint doesn't match, so even though uid matches, it fails
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void gpgFingerprintIgnoredForV6() {
            var member = new TrustConfig.Member(
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", null, null);
            var sig = new SignatureInfo(6,
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "ML-DSA", null, VerificationResult.PASS);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void notPresentAlwaysFalse() {
            var member = new TrustConfig.Member(null, null, "Alice <alice@example.com>");
            var sig = new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void failResultNeverMatchesGpg() {
            var member = new TrustConfig.Member(
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", null, null);
            var sig = new SignatureInfo(4,
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "RSA", "Alice <alice@example.com>", VerificationResult.FAIL);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void failResultNeverMatchesPqc() {
            var member = new TrustConfig.Member(null,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991", null);
            var sig = new SignatureInfo(6,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991",
                    "ML-DSA", null, VerificationResult.FAIL);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }

        @Test
        void failResultNeverMatchesUid() {
            var member = new TrustConfig.Member(null, null, "Alice <alice@example.com>");
            var sig = new SignatureInfo(4, "KEYID1234567890AB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.FAIL);
            assertFalse(VerifyMojo.memberMatchesSignature(member, sig));
        }
    }

    @Nested
    class PomVerificationTests {

        private ArtifactCoords jarArtifact(String groupId, String artifactId, String version) {
            return new ArtifactCoords(groupId, artifactId, "", "jar", version);
        }

        @Test
        void addPomArtifactsCreatesPomForEachJar() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib-a", "1.0"));
            artifacts.add(jarArtifact("com.example", "lib-b", "2.0"));

            mojo.addPomArtifacts(artifacts, null);

            assertEquals(4, artifacts.size());
            ArtifactCoords pomA = artifacts.get(2);
            assertEquals("com.example", pomA.groupId());
            assertEquals("lib-a", pomA.artifactId());
            assertEquals("pom", pomA.type());
            assertEquals("1.0", pomA.version());

            ArtifactCoords pomB = artifacts.get(3);
            assertEquals("lib-b", pomB.artifactId());
            assertEquals("pom", pomB.type());
        }

        @Test
        void addPomArtifactsSkipsExistingPomArtifacts() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(new ArtifactCoords(
                    "com.example", "parent", "", "pom", "1.0"));

            mojo.addPomArtifacts(artifacts, null);

            assertEquals(1, artifacts.size());
        }

        @Test
        void addPomArtifactsInheritsSignerRefs() {
            var mojo = new VerifyMojo();
            ArtifactCoords jar = jarArtifact("com.example", "lib", "1.0");
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jar);

            Map<String, List<String>> refs = new HashMap<>();
            refs.put("com.example:lib:1.0", List.of("alice"));

            mojo.addPomArtifacts(artifacts, refs);

            assertEquals(List.of("alice"), refs.get("com.example:lib:pom:1.0"));
        }
    }
}
