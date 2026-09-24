package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link DefaultTrustPolicy} including the {@code EMPTY} constant,
 * constructor behavior, and signer matching.
 */
class DefaultTrustPolicyTest {

    @Nested
    class EmptyConstant {

        @Test
        void emptyHasAllListedEvidencePolicy() {
            assertThat(DefaultTrustPolicy.EMPTY.listedEvidence()).isEqualTo(ListedEvidencePolicy.ALL);
        }

        @Test
        void emptyHasIgnoreUnlistedEvidencePolicy() {
            assertThat(DefaultTrustPolicy.EMPTY.unlistedEvidence()).isEqualTo(UnlistedEvidencePolicy.IGNORE);
        }

        @Test
        void emptyHasFailUntrustedPolicy() {
            assertThat(DefaultTrustPolicy.EMPTY.onUntrusted()).isEqualTo(UntrustedPolicy.FAIL);
        }

        @Test
        void emptyReturnsNoExpectedSigners() {
            var artifact = testArtifact("org.example", "lib", "1.0");
            assertThat(DefaultTrustPolicy.EMPTY.expectedSigners(artifact).isEmpty()).isTrue();
        }
    }

    @Nested
    class ConstructorBehavior {

        @Test
        void listedEvidencePolicy() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ALL,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);
            assertThat(policy.listedEvidence()).isEqualTo(ListedEvidencePolicy.ALL);
        }

        @Test
        void unlistedEvidencePolicy() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ANY,
                    UnlistedEvidencePolicy.WARN, UntrustedPolicy.FAIL);
            assertThat(policy.unlistedEvidence()).isEqualTo(UnlistedEvidencePolicy.WARN);
        }

        @Test
        void untrustedPolicy() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ANY,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.WARN);
            assertThat(policy.onUntrusted()).isEqualTo(UntrustedPolicy.WARN);
        }

        @Test
        void storesAllValues() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of(), ListedEvidencePolicy.ANY,
                    UnlistedEvidencePolicy.REQUIRE, UntrustedPolicy.WARN);
            assertThat(policy.listedEvidence()).isEqualTo(ListedEvidencePolicy.ANY);
            assertThat(policy.unlistedEvidence()).isEqualTo(UnlistedEvidencePolicy.REQUIRE);
            assertThat(policy.onUntrusted()).isEqualTo(UntrustedPolicy.WARN);
        }
    }

    @Nested
    class SignerMatching {

        @Test
        void expectedSignersReturnsEmptyForUnmatchedPattern() {
            var signer = new SignerIdentity("alice", "Alice",
                    List.of(new FingerprintCredential("openpgp4", "AABB")));
            var policy = new DefaultTrustPolicy(
                    Map.of("org.example:*", List.of(signer)),
                    List.of(), ListedEvidencePolicy.ALL,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);

            var unmatched = testArtifact("com.other", "lib", "1.0");
            assertThat(policy.expectedSigners(unmatched).isEmpty()).isTrue();
        }

        @Test
        void expectedSignersReturnsSignersForMatchedPattern() {
            var signer = new SignerIdentity("alice", "Alice",
                    List.of(new FingerprintCredential("openpgp4", "AABB")));
            var policy = new DefaultTrustPolicy(
                    Map.of("org.example:*", List.of(signer)),
                    List.of(), ListedEvidencePolicy.ALL,
                    UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);

            var matched = testArtifact("org.example", "lib", "1.0");
            var signers = policy.expectedSigners(matched);
            assertThat(signers).isNotNull();
            assertThat(signers.size()).isEqualTo(1);
            assertThat(signers.get(0).id()).isEqualTo("alice");
        }
    }

    private static ArtifactCoords testArtifact(String ns, String name, String version) {
        return new ArtifactCoords(ns, name, "", "jar", version);
    }
}
