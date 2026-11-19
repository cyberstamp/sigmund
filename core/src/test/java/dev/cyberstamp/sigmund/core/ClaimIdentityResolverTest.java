package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ClaimIdentityResolverTest {

    private static final ArtifactCoords COORDS = ArtifactCoords.parse("org.example:lib:1.0");
    private static final String PINNED = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final String NEW_KEY = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";
    private static final String ADDRESS = "release@example.org";
    private static final String DIRECTORY = IssuerKind.KEYS_OPENPGP_ORG;

    private final FakeDirectory directory = new FakeDirectory();

    @Nested
    class WhenPolicyNamesASignerByAddress {

        private final SignerIdentity release = new SignerIdentity("release", List.of(
                KeyCredential.openPgp(PINNED),
                IdentityCredential.email(null, ADDRESS)));

        @Test
        void aNewKeyIsAcceptedOnTheStrengthOfTheDirectory() {
            directory.addresses.put(NEW_KEY, List.of(ADDRESS));
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(claims.get(0).attesterCredentials())
                    .contains(IdentityCredential.email(DIRECTORY, ADDRESS));
            assertThat(satisfied(policy, claims)).isTrue();
        }

        @Test
        void aPinnedKeyNeedsNoLookup() {
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(PINNED));

            assertThat(directory.asked).isEmpty();
            assertThat(satisfied(policy, claims)).isTrue();
        }

        @Test
        void aKeyTheDirectoryVouchesForUnderAnotherAddressIsNotAccepted() {
            directory.addresses.put(NEW_KEY, List.of("someone@example.org"));
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(satisfied(policy, claims)).isFalse();
        }

        @Test
        void anUnreachableDirectoryLeavesTheClaimIndeterminate() {
            directory.failing = true;
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(claims.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE))
                    .isTrue();
            assertThat(claims.get(0).attesterCredentials())
                    .containsExactly(KeyCredential.openPgp(NEW_KEY));
        }

        @Test
        void disabledLookupsLeaveTheClaimIndeterminateWithoutAsking() {
            TrustPolicy policy = policy(release, List.of(DIRECTORY));

            List<ClaimResult> claims = new ClaimIdentityResolver(policy,
                    Map.of(DIRECTORY, directory), false).resolve(COORDS, List.of(claim(NEW_KEY)));

            assertThat(directory.asked).isEmpty();
            assertThat(claims.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE))
                    .isTrue();
        }

        @Test
        void aFailedSignatureIsNeverLookedUp() {
            TrustPolicy policy = policy(release, List.of(DIRECTORY));
            ClaimResult failed = new ClaimResult("openpgp", ClaimOutcome.FAILED, null, List.of(),
                    null, TrustRootRef.unknown(), evidence(), null,
                    ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");

            resolve(policy, failed);

            assertThat(directory.asked).isEmpty();
        }
    }

    @Nested
    class WhenNoDirectoryCanVouch {

        @Test
        void aSignerNamedOnlyByKeyNeedsNoLookup() {
            SignerIdentity pinnedOnly = new SignerIdentity("release", List.of(KeyCredential.openPgp(PINNED)));

            resolve(policy(pinnedOnly, List.of(DIRECTORY)), claim(NEW_KEY));

            assertThat(directory.asked).isEmpty();
        }

        @Test
        void anAddressVouchedForOnlyByAnOidcIssuerNeedsNoLookup() {
            SignerIdentity oidcOnly = new SignerIdentity("release", List.of(
                    IdentityCredential.email("https://accounts.google.com", ADDRESS)));

            resolve(policy(oidcOnly, List.of()), claim(NEW_KEY));

            assertThat(directory.asked).isEmpty();
        }

        @Test
        void aDirectoryNamedInlineIsAskedWithoutBeingListed() {
            directory.addresses.put(NEW_KEY, List.of(ADDRESS));
            SignerIdentity inline = new SignerIdentity("release", List.of(
                    IdentityCredential.email(DIRECTORY, ADDRESS)));
            TrustPolicy policy = policy(inline, List.of());

            List<ClaimResult> claims = resolve(policy, claim(NEW_KEY));

            assertThat(satisfied(policy, claims)).isTrue();
        }
    }

    @Nested
    class ForGivenSigners {

        @Test
        void aPinnedKeyCostsNoLookup() {
            SignerIdentity pinned = new SignerIdentity("release", List.of(KeyCredential.openPgp(PINNED)));
            ClaimResult claim = claim(PINNED);

            List<ClaimResult> resolved = new ClaimIdentityResolver(Map.of(DIRECTORY, directory), true)
                    .resolve(List.of(pinned), List.of(DIRECTORY), List.of(claim));

            assertThat(resolved).containsExactly(claim);
            assertThat(directory.asked).isEmpty();
        }

        @Test
        void anUnpinnedKeyIsLookedUpForAnAddressSigner() {
            directory.addresses.put(NEW_KEY, List.of(ADDRESS));

            List<ClaimResult> resolved = new ClaimIdentityResolver(Map.of(DIRECTORY, directory), true)
                    .resolve(List.of(addressSigner()), List.of(DIRECTORY), List.of(claim(NEW_KEY)));

            assertThat(resolved.get(0).attesterCredentials())
                    .contains(IdentityCredential.email(DIRECTORY, ADDRESS));
        }

        @Test
        void lookupsDisabledLeaveTheClaimKeyUnavailable() {
            directory.addresses.put(NEW_KEY, List.of(ADDRESS));

            List<ClaimResult> resolved = new ClaimIdentityResolver(Map.of(DIRECTORY, directory), false)
                    .resolve(List.of(addressSigner()), List.of(DIRECTORY), List.of(claim(NEW_KEY)));

            assertThat(resolved.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE))
                    .isTrue();
            assertThat(directory.asked).isEmpty();
        }

        private SignerIdentity addressSigner() {
            return new SignerIdentity("release", List.of(IdentityCredential.email(null, ADDRESS)));
        }
    }

    @Nested
    class VouchingForDisplayNames {

        private static final String UID = "Alice Example <alice@example.org>";
        private static final String UBUNTU = "hkps://keyserver.ubuntu.com";
        private static final String OPENPGP_ORG = "hkps://keys.openpgp.org";

        @TempDir
        Path dir;

        @Test
        void aUserIdTheDirectoryServedIsVouchedWhenListed() throws Exception {
            PGPPublicKeyRing ring = ring(UID);
            ClaimResult claim = openPgpClaim(ring, UID, "bc");

            List<ClaimResult> vouched = vouch(directoryServing(OPENPGP_ORG, ring), List.of(DIRECTORY), claim);

            assertThat(vouched.get(0).displayNameVouchedBy()).isEqualTo(DIRECTORY);
            assertThat(vouched.get(0).labeledDisplayName())
                    .isEqualTo(UID + " (address verified by keys.openpgp.org)");
        }

        @Test
        void notWhenTheDirectoryIsNotListed() throws Exception {
            PGPPublicKeyRing ring = ring(UID);
            ClaimResult claim = openPgpClaim(ring, UID, "bc");

            List<ClaimResult> vouched = vouch(directoryServing(OPENPGP_ORG, ring), List.of(), claim);

            assertThat(vouched.get(0).displayNameVouchedBy()).isNull();
            assertThat(vouched.get(0).labeledDisplayName()).isEqualTo(UID + " (unverified)");
        }

        @Test
        void notWhenOnlyAnotherKeyserverServedIt() throws Exception {
            PGPPublicKeyRing ring = ring(UID);

            List<ClaimResult> vouched = vouch(directoryServing(UBUNTU, ring), List.of(DIRECTORY),
                    openPgpClaim(ring, UID, "bc"));

            assertThat(vouched.get(0).displayNameVouchedBy()).isNull();
        }

        @Test
        void notForAKeyFromALocalStore() throws Exception {
            PGPPublicKeyRing ring = ring(UID);
            BcKeyStore store = store();
            store.storeCert(ring);
            KeysOpenPgpOrgDirectory real = new KeysOpenPgpOrgDirectory("http://127.0.0.1:1");
            real.answerFrom(store);

            List<ClaimResult> vouched = vouch(real, List.of(DIRECTORY), openPgpClaim(ring, UID, "bc"));

            assertThat(vouched.get(0).displayNameVouchedBy()).isNull();
        }

        @Test
        void aDifferentDisplayedUserIdIsNotVouched() throws Exception {
            PGPPublicKeyRing ring = ring(UID);

            List<ClaimResult> vouched = vouch(directoryServing(OPENPGP_ORG, ring), List.of(DIRECTORY),
                    openPgpClaim(ring, "Mallory <alice@example.org>", "bc"));

            assertThat(vouched.get(0).displayNameVouchedBy()).isNull();
        }

        @Test
        void theSameClaimAnsweredBySqGetsTheSameLabel() throws Exception {
            PGPPublicKeyRing ring = ring(UID);
            KeysOpenPgpOrgDirectory served = directoryServing(OPENPGP_ORG, ring);

            ClaimResult bc = vouch(served, List.of(DIRECTORY), openPgpClaim(ring, UID, "bc")).get(0);
            ClaimResult sq = vouch(served, List.of(DIRECTORY), openPgpClaim(ring, UID, "sq")).get(0);

            assertThat(sq.labeledDisplayName()).isEqualTo(bc.labeledDisplayName());
        }

        @Test
        void aSigstoreClaimIsAttestedByItsListedIssuer() {
            String google = "https://accounts.google.com";

            List<ClaimResult> vouched = vouch(new FakeDirectory(), List.of(google), sigstoreClaim(google));

            assertThat(vouched.get(0).labeledDisplayName())
                    .isEqualTo("alice@example.org (attested by " + google + ")");
        }

        @Test
        void notWhenItsIssuerIsNotListed() {
            List<ClaimResult> vouched = vouch(new FakeDirectory(), List.of(DIRECTORY),
                    sigstoreClaim("https://accounts.google.com"));

            assertThat(vouched.get(0).labeledDisplayName()).isEqualTo("alice@example.org (unverified)");
        }

        private List<ClaimResult> vouch(OpenPgpDirectory served, List<String> issuers, ClaimResult claim) {
            return new ClaimIdentityResolver(Map.of(DIRECTORY, served), true)
                    .vouchForDisplayNames(issuers, List.of(claim));
        }

        private KeysOpenPgpOrgDirectory directoryServing(String keyserver, PGPPublicKeyRing ring) {
            BcKeyStore store = store();
            BcTestKeys.addFetched(store, Map.of(keyserver, ring));
            KeysOpenPgpOrgDirectory real = new KeysOpenPgpOrgDirectory("http://127.0.0.1:1");
            real.answerFrom(store);
            return real;
        }

        private BcKeyStore store() {
            return new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc-private"));
        }

        private static PGPPublicKeyRing ring(String userId) throws Exception {
            return new BcOpenPGPApi().generateKey(PublicKeyPacket.VERSION_4)
                    .ed25519x25519Key(userId).build().toCertificate().getPGPPublicKeyRing();
        }

        private static ClaimResult openPgpClaim(PGPPublicKeyRing ring, String displayed, String tool) {
            String fingerprint = KeyRingFiles.hex(ring.getPublicKey().getFingerprint());
            OpenPgpVerifyResult result = OpenPgpVerifyResult.verified(displayed, "Ed25519", 4,
                    fingerprint.substring(24), fingerprint);
            return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(KeyCredential.openPgp(fingerprint)), displayed, TrustRootRef.unknown(),
                    evidence(), null, ClaimTimeSource.SIGNER, Instant.EPOCH, "Ed25519", tool, null,
                    null, result, null);
        }

        private static ClaimResult sigstoreClaim(String issuer) {
            IdentityCredential identity = IdentityCredential.email(issuer, "alice@example.org");
            SigstoreVerifyResult result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null,
                    "alice@example.org", "ECDSA", identity, null, 1);
            return new ClaimResult("sigstore", ClaimOutcome.VERIFIED, null, List.of(identity),
                    "alice@example.org", TrustRootRef.unknown(), evidence(), null,
                    ClaimTimeSource.SIGNER, Instant.EPOCH, "ECDSA", "sigstore", null, null, result, null);
        }
    }

    private List<ClaimResult> resolve(TrustPolicy policy, ClaimResult claim) {
        return new ClaimIdentityResolver(policy, Map.of(DIRECTORY, directory), true)
                .resolve(COORDS, List.of(claim));
    }

    private static TrustPolicy policy(SignerIdentity signer, List<String> issuers) {
        var signers = new SignersConfig(Map.of(signer.id(), signer));
        var spec = new TrustPolicySpec(
                List.of(new RuleSpec(List.of(ArtifactPattern.parse("org.example")),
                        List.of(Set.of(signer.id())), Map.of(), "rules[0]", null)),
                ClaimSetMode.ALL_CLAIMS, Map.of(), issuers, true);
        return RulePolicy.compile(spec, signers);
    }

    private static boolean satisfied(TrustPolicy policy, List<ClaimResult> claims) {
        List<ClaimResult> verified = claims.stream()
                .filter(c -> c.outcome() == ClaimOutcome.VERIFIED).toList();
        Rule rule = policy.matchRule(COORDS);
        return rule != null && rule.requirement().evaluate(verified).satisfied();
    }

    private static ClaimResult claim(String fingerprint) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                List.of(KeyCredential.openPgp(fingerprint)), "Anyone <" + ADDRESS + ">",
                TrustRootRef.unknown(), evidence(), null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static EvidenceRef evidence() {
        return new EvidenceRef(Path.of("lib-1.0.jar.asc"),
                DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                Evidence.SOURCE_SIDECAR);
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
