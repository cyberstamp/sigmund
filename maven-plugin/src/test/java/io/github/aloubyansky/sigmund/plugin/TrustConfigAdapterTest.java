package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import io.github.aloubyansky.sigmund.core.ArtifactIdentity;
import io.github.aloubyansky.sigmund.core.Credential;
import io.github.aloubyansky.sigmund.core.SignerIdentity;
import io.github.aloubyansky.sigmund.core.TrustPolicy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TrustConfigAdapterTest {

    @Nested
    class SignerConversion {

        @Test
        void pgp4Fingerprint() {
            TrustConfig config = config(
                    Map.of("alice", signer(null, List.of(member("FP4", null, null)))),
                    Map.of("com.example:lib", List.of("alice")));

            TrustPolicy policy = adapt(config).trustPolicy();
            List<SignerIdentity> signers = policy.expectedSigners(artifact("com.example", "lib"));

            assertEquals(1, signers.size());
            assertEquals(1, signers.get(0).credentials().size());
            assertEquals(Credential.TYPE_OPENPGP_V4, signers.get(0).credentials().get(0).type());
        }

        @Test
        void pgp6Fingerprint() {
            TrustConfig config = config(
                    Map.of("bob", signer(null, List.of(member(null, "FP6", null)))),
                    Map.of("com.example:lib", List.of("bob")));

            TrustPolicy policy = adapt(config).trustPolicy();
            List<SignerIdentity> signers = policy.expectedSigners(artifact("com.example", "lib"));

            assertEquals(Credential.TYPE_OPENPGP_V6, signers.get(0).credentials().get(0).type());
        }

        @Test
        void emailCredential() {
            TrustConfig config = config(
                    Map.of("carol", signer(null, List.of(member(null, null, "carol@example.com")))),
                    Map.of("com.example:lib", List.of("carol")));

            TrustPolicy policy = adapt(config).trustPolicy();
            List<SignerIdentity> signers = policy.expectedSigners(artifact("com.example", "lib"));

            assertEquals(Credential.TYPE_EMAIL, signers.get(0).credentials().get(0).type());
        }

        @Test
        void allThreeCredentials() {
            TrustConfig config = config(
                    Map.of("dave", signer(null, List.of(member("FP4", "FP6", "dave@example.com")))),
                    Map.of("com.example:lib", List.of("dave")));

            TrustPolicy policy = adapt(config).trustPolicy();
            assertEquals(3, policy.expectedSigners(artifact("com.example", "lib"))
                    .get(0).credentials().size());
        }

        @Test
        void displayNameFromSignerName() {
            TrustConfig config = config(
                    Map.of("ref", signer("Alice Smith", List.of(member("FP4", null, null)))),
                    Map.of("com.example:lib", List.of("ref")));

            TrustPolicy policy = adapt(config).trustPolicy();
            assertEquals("Alice Smith",
                    policy.expectedSigners(artifact("com.example", "lib")).get(0).displayName());
        }

        @Test
        void displayNameFallsBackToRef() {
            TrustConfig config = config(
                    Map.of("alice", signer(null, List.of(member("FP4", null, null)))),
                    Map.of("com.example:lib", List.of("alice")));

            TrustPolicy policy = adapt(config).trustPolicy();
            assertEquals("alice",
                    policy.expectedSigners(artifact("com.example", "lib")).get(0).displayName());
        }
    }

    @Nested
    class PolicySettings {

        @Test
        void verifyAllSignaturesTrue() {
            TrustConfig config = config(
                    Map.of("a", signer(null, List.of(member("FP", null, null)))),
                    Map.of("com.example:lib", List.of("a")));

            TrustPolicy policy = adapt(config, settings(true, "fail")).trustPolicy();
            assertTrue(policy.requireAllEvidenceMatch());
        }

        @Test
        void verifyAllSignaturesFalse() {
            TrustConfig config = config(
                    Map.of("a", signer(null, List.of(member("FP", null, null)))),
                    Map.of("com.example:lib", List.of("a")));

            TrustPolicy policy = adapt(config, settings(false, "fail")).trustPolicy();
            assertFalse(policy.requireAllEvidenceMatch());
        }

        @Test
        void onUntrustedProducesDistinctPolicies() {
            TrustConfig config = config(
                    Map.of("a", signer(null, List.of(member("FP", null, null)))),
                    Map.of("com.example:lib", List.of("a")));

            TrustPolicy failPolicy = adapt(config, settings(true, "fail")).trustPolicy();
            TrustPolicy warnPolicy = adapt(config, settings(true, "warn")).trustPolicy();
            assertNotEquals(failPolicy, warnPolicy);
        }
    }

    @Nested
    class TrustMappings {

        @Test
        void unknownSignerRefSkipped() {
            TrustConfig config = config(
                    Map.of("alice", signer(null, List.of(member("FP", null, null)))),
                    Map.of("com.example:lib", List.of("nonexistent")));

            TrustPolicy policy = adapt(config).trustPolicy();
            var signers = policy.expectedSigners(artifact("com.example", "lib"));
            assertTrue(signers == null || signers.isEmpty());
        }

        @Test
        void artifactGroupExpansion() {
            TrustConfig config = new TrustConfig(
                    TrustConfig.Settings.defaults(),
                    Map.of("alice", signer(null, List.of(member("FP", null, null)))),
                    Map.of("apache-commons", List.of("org.apache.commons:commons-lang3",
                            "org.apache.commons:commons-io")),
                    Map.of("apache-commons", List.of("alice")),
                    List.of());

            TrustPolicy policy = adapt(config).trustPolicy();
            assertNotNull(policy.expectedSigners(artifact("org.apache.commons", "commons-lang3")));
            assertNotNull(policy.expectedSigners(artifact("org.apache.commons", "commons-io")));
        }

        @Test
        void unsignedPatterns() {
            TrustConfig config = new TrustConfig(
                    TrustConfig.Settings.defaults(),
                    Map.of(),
                    Map.of(),
                    Map.of(),
                    List.of("com.internal:*"));

            TrustPolicy policy = adapt(config).trustPolicy();
            assertTrue(policy.isUnsignedAllowed(artifact("com.internal", "lib")));
            assertFalse(policy.isUnsignedAllowed(artifact("com.example", "lib")));
        }
    }

    // --- Helpers ---

    private static TrustConfigAdapter adapt(TrustConfig config) {
        return new TrustConfigAdapter(config, config.settings());
    }

    private static TrustConfigAdapter adapt(TrustConfig config, TrustConfig.Settings settings) {
        return new TrustConfigAdapter(config, settings);
    }

    private static TrustConfig config(Map<String, TrustConfig.Signer> signers,
            Map<String, List<String>> trust) {
        return new TrustConfig(TrustConfig.Settings.defaults(), signers, Map.of(), trust, List.of());
    }

    private static TrustConfig.Settings settings(boolean verifyAll, String onUntrusted) {
        return new TrustConfig.Settings(List.of(), onUntrusted, verifyAll, true);
    }

    private static TrustConfig.Signer signer(String name, List<TrustConfig.Member> members) {
        return new TrustConfig.Signer(name, members);
    }

    private static TrustConfig.Member member(String pgp4, String pgp6, String email) {
        return new TrustConfig.Member(pgp4, pgp6, email);
    }

    private static ArtifactIdentity artifact(String groupId, String artifactId) {
        return new ArtifactIdentity() {
            @Override
            public String namespace() {
                return groupId;
            }

            @Override
            public String name() {
                return artifactId;
            }

            @Override
            public String version() {
                return "1.0";
            }
        };
    }
}
