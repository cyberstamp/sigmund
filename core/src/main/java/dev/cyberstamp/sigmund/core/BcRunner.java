package dev.cyberstamp.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPDetachedSignatureProcessor;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * Pure-Java OpenPGP signing and verification tool using Bouncy Castle.
 *
 * <p>
 * Handles v4 and v6 signatures for classic algorithms (Ed25519, Ed448,
 * RSA, ECDSA). Always available — no external process dependencies.
 *
 * <p>
 * Instances are obtained from {@link BcToolFactory}, not constructed directly: the
 * constructors take a package-private {@link BcKeyStore}, so the factory is the only way to
 * build one from configuration. That keeps key-store layout — GnuPG home, cert-d store,
 * private key directory — an implementation detail of core rather than part of the API.
 *
 * @see BcToolFactory
 * @see BcKeyStore
 */
class BcRunner implements AutoCloseable, SignatureTool, KeyGenerator, KeyImporter, SecretKeyExporter,
        CertExporter, SignerIdentityResolver, SignerInspection {

    private static final String NAME = "bc";

    /** The cipher suite keys are generated with when neither the caller nor the config names one. */
    static final String DEFAULT_CIPHER_SUITE = "ed25519";

    private static final String SOURCE_LOCAL = "local";
    private static final String SOURCE_HKP = "hkp";

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of(
            Credential.TYPE_PGP4, Credential.TYPE_PGP6);

    /**
     * The algorithm policy for verification, shared with the other OpenPGP backends: see
     * {@link VerificationAlgorithms}.
     */
    private static final OpenPGPPolicy VERIFICATION_POLICY = VerificationAlgorithms.bouncyCastlePolicy();

    private final BcOpenPGPApi api;
    private final BcKeyStore keyStore;
    private final List<String> signingFingerprints;
    private final Path tskFile;
    private final byte[] tskBytes;
    private final PassphraseProvider passphraseProvider;
    private final OpenPgpSignatureFormat format;
    private final KeyserverFetcher fetcher;
    private final String defaultCipherSuite;
    /**
     * The certificates of the keys this runner has signed with, by primary fingerprint, empty
     * until it has signed. Consulted by {@link #certificateFor(String)} only when no store holds
     * the key a signature names; a signature verified against one is still checked
     * cryptographically.
     */
    private final Map<String, PGPPublicKeyRing> signingCertificates = new ConcurrentHashMap<>();

    /**
     * Returns the key store this runner looks keys up in.
     *
     * @return the key store
     */
    BcKeyStore keyStore() {
        return keyStore;
    }

    /**
     * Creates a new BC runner without passphrase support or key fetching.
     *
     * @param keyStore the key store for key lookup and storage
     * @param signingFingerprint the fingerprint of the key to sign with, or {@code null}
     * @param tskFile the path to a TSK file for signing, or {@code null}
     */
    BcRunner(BcKeyStore keyStore, String signingFingerprint, Path tskFile) {
        this(keyStore, signingFingerprint, tskFile, null, null, null);
    }

    /**
     * Creates a new BC runner.
     *
     * @param keyStore the key store for key lookup and storage
     * @param signingFingerprint the fingerprint of the key to sign with, or {@code null}
     * @param tskFile the path to a TSK file for signing, or {@code null}
     * @param passphraseProvider provides passphrases for encrypted keys, or {@code null}
     */
    BcRunner(BcKeyStore keyStore, String signingFingerprint, Path tskFile,
            PassphraseProvider passphraseProvider) {
        this(keyStore, signingFingerprint, tskFile, null, passphraseProvider, null);
    }

    /**
     * Creates a new BC runner with full key fetching configuration.
     *
     * @param keyStore the key store for key lookup and storage
     * @param signingFingerprint the fingerprint of the key to sign with, or {@code null}
     * @param tskFile the path to a TSK file for signing, or {@code null}
     * @param tskBytes raw TSK key material (e.g. from an env var), or {@code null}
     * @param passphraseProvider provides passphrases for encrypted keys, or {@code null}
     * @param fetcher fetches missing keys from keyservers, or {@code null} when keys are not
     *        fetched
     */
    BcRunner(BcKeyStore keyStore, String signingFingerprint, Path tskFile,
            byte[] tskBytes, PassphraseProvider passphraseProvider,
            KeyserverFetcher fetcher) {
        this(keyStore, signingFingerprint == null ? List.of() : List.of(signingFingerprint), tskFile,
                tskBytes, passphraseProvider, fetcher, DEFAULT_CIPHER_SUITE);
    }

    /**
     * Creates a new BC runner that signs with the named keys and generates keys with the given
     * cipher suite by default.
     * <p>
     * A TSK file or key material takes the place of the named keys: the runner then signs with
     * that one key.
     *
     * @param keyStore the key store for key lookup and storage
     * @param signingFingerprints the fingerprints of the keys to sign with, in order; empty when
     *        no key is named
     * @param tskFile the path to a TSK file for signing, or {@code null}
     * @param tskBytes raw TSK key material (e.g. from an env var), or {@code null}
     * @param passphraseProvider provides passphrases for encrypted keys, or {@code null}
     * @param fetcher fetches missing keys from keyservers, or {@code null} when keys are not
     *        fetched
     * @param defaultCipherSuite the suite {@link #generateKey(String, String, String)} uses when given none
     */
    BcRunner(BcKeyStore keyStore, List<String> signingFingerprints, Path tskFile,
            byte[] tskBytes, PassphraseProvider passphraseProvider,
            KeyserverFetcher fetcher, String defaultCipherSuite) {
        this.defaultCipherSuite = defaultCipherSuite;
        this.api = new BcOpenPGPApi();
        this.keyStore = keyStore;
        this.signingFingerprints = List.copyOf(signingFingerprints);
        this.tskFile = tskFile;
        this.tskBytes = tskBytes != null ? tskBytes.clone() : null;
        this.passphraseProvider = passphraseProvider;
        this.format = new OpenPgpSignatureFormat();
        this.fetcher = fetcher;
    }

    @Override
    public String name() {
        return NAME;
    }

    /**
     * Releases the keyserver fetcher's HTTP client, if keys are fetched.
     */
    @Override
    public void close() {
        if (fetcher != null) {
            fetcher.close();
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Always returns {@code true} — BC is a pure-Java library.
     */
    @Override
    public boolean isAvailable() {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Returns {@code true} if a signing fingerprint, a TSK file or key material was provided.
     */
    @Override
    public boolean canSign() {
        return !signingFingerprints.isEmpty() || tskFile != null || tskBytes != null;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Gives one entry for a TSK file or key material, otherwise one per named key, in order. A
     * named key is typed from its fingerprint's length when the store does not hold it; a TSK
     * that cannot be read gets an entry with a {@code null} credential type, named by the TSK
     * file's name or {@code "(env var key)"}.
     */
    @Override
    public List<SigningInfo> signingInfo() {
        if (!canSign()) {
            return List.of();
        }
        if (tskBytes != null) {
            return List.of(describeOwnKey("(env var key)"));
        }
        if (tskFile != null) {
            return List.of(describeOwnKey(tskFile.getFileName().toString()));
        }
        return signingFingerprints.stream().map(this::describeNamedKey).toList();
    }

    private SigningInfo describeOwnKey(String label) {
        try {
            return describe(loadOwnKey());
        } catch (IOException | PGPException e) {
            return new SigningInfo(NAME, label, null, null, null);
        }
    }

    private SigningInfo describeNamedKey(String fingerprint) {
        try {
            return describe(loadNamedKey(fingerprint));
        } catch (ToolExecutionException e) {
            return new SigningInfo(NAME, fingerprint, null, null, KeyCredential.openPgp(fingerprint).type());
        }
    }

    /**
     * Describes a signing key by its own certificate, the one the secret key ring carries: a
     * public copy in a store may be a merge of what keyservers served, and a user ID one of them
     * added could come first there.
     */
    private SigningInfo describe(PGPSecretKeyRing ring) {
        PGPPublicKey pub = ring.getPublicKey();
        String fp = KeyRingFiles.hex(pub.getFingerprint());
        String type = pub.getVersion() >= 6 ? Credential.TYPE_PGP6 : Credential.TYPE_PGP4;
        Iterator<String> userIds = pub.getUserIDs();
        return new SigningInfo(NAME, fp, Algorithms.algorithmName(pub.getAlgorithm()),
                userIds.hasNext() ? userIds.next() : null, type);
    }

    @Override
    public SignatureFormat signatureFormat() {
        return format;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return SUPPORTED_CREDENTIAL_TYPES;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Bouncy Castle verifies against the cert-d store, plus any key fetched into the
     * in-memory cache for this session.
     */
    @Override
    public TrustRootRef trustRoot() {
        return TrustRootRef.certD(keyStore.certDHome());
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Accepts an {@link OpenPgpClaim} of any packet version, except a post-quantum signature
     * ({@link Algorithms#isPqcAlgorithm(int)}): Bouncy Castle 1.86 cannot read an ML-DSA or
     * SLH-DSA key at all — parsing the certificate fails with "unknown signature key algorithm" —
     * so it could only report such a key as missing, and would look for it on keyservers. Declining
     * passes the claim to a tool that reads it, or leaves it {@code UNSUPPORTED_ALGORITHM} when
     * none does. {@code BcPostQuantumTest} fails once a Bouncy Castle upgrade reads these keys.
     */
    @Override
    public boolean canVerify(Claim claim) {
        return claim instanceof OpenPgpClaim openPgp
                && !Algorithms.isPqcAlgorithm(openPgp.algorithmId());
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Verifies a detached OpenPGP signature using Bouncy Castle.
     */
    @Override
    public VerifyResult verify(Path artifactFile, Claim claim) {
        if (!(claim instanceof OpenPgpClaim opgu)) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        return verifyOpenPgpClaim(artifactFile, opgu);
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Creates a detached ASCII-armored signature. A TSK file or key material signs whatever
     * {@code key} names; otherwise {@code key} must be one of the named keys, and is loaded from
     * the key store.
     *
     * @throws IllegalStateException if {@link #canSign()} is {@code false}
     * @throws IllegalArgumentException if no TSK is configured and {@code key} is not one of
     *         the named keys
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig, SigningInfo key) {
        if (!canSign()) {
            throw new IllegalStateException("No signing key configured");
        }
        try {
            PGPSecretKeyRing secretKeyRing = loadSigningKey(key);
            PGPPublicKeyRing certificate = certificateOf(secretKeyRing);
            signingCertificates.put(KeyRingFiles.hex(certificate.getPublicKey().getFingerprint()),
                    certificate);
            return signWithKey(artifactFile, outputSig, secretKeyRing);
        } catch (IOException e) {
            throw new ToolExecutionException("Signing failed", e);
        } catch (PGPException e) {
            throw new ToolExecutionException("Signing failed: " + e.getMessage(), e);
        }
    }

    @Override
    public List<Credential> extractCredentials(VerifyResult result) {
        return OpenPgpCredentials.from(result);
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Generates a key using BC 1.85's high-level {@code BcOpenPGPApi}. Without a cipher suite,
     * the one {@code tools.bc.cipher-suite} configures is used, else {@value #DEFAULT_CIPHER_SUITE}.
     * Without a credential type the key is v4 ({@code pgp4}), the version keyservers serve and
     * GnuPG signs with; {@code pgp6} gives a v6 key, for {@code ed25519}, {@code ed448} and
     * {@code rsa4096} only.
     */
    @Override
    public String generateKey(String userId, String cipherSuite, String credentialType) {
        try {
            OpenPGPKey key = generateKeyInternal(userId,
                    cipherSuite != null ? cipherSuite : defaultCipherSuite, keyVersion(credentialType));
            PGPSecretKeyRing secretKeyRing = key.getPGPSecretKeyRing();
            PGPPublicKeyRing publicKeyRing = key.toCertificate().getPGPPublicKeyRing();
            String fingerprint = KeyRingFiles.hex(key.getFingerprint());
            secretKeyRing = encryptKeyRing(secretKeyRing, fingerprint);
            keyStore.storeCert(publicKeyRing);
            keyStore.storeSecretKey(secretKeyRing);
            return fingerprint;
        } catch (Exception e) {
            throw new ToolExecutionException("Key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * BC can always fetch, whether the key store keeps fetched keys in memory or persists
     * them. Returns {@code true} when a keyserver fetcher is configured.
     */
    @Override
    public boolean canFetchKeys() {
        return fetcher != null;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Delegates to the {@link KeyserverFetcher}, which adds what it fetches to the key store.
     */
    @Override
    public boolean fetchKey(String keyId) {
        return fetcher != null && fetcher.fetch(keyId);
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Exports the public certificate as an ASCII-armored string.
     */
    @Override
    public String exportCert(String fingerprint) {
        BcKeyStore.KeyLookup found = keyStore.findPublicKey(fingerprint);
        if (found == null) {
            throw new ToolExecutionException("Certificate not found: " + fingerprint);
        }
        return armorKeyRing(found.ring());
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Reads the key from the private store, where {@code keygen} writes it, as it was stored —
     * encrypted when it was generated with a passphrase.
     */
    @Override
    public String exportSecretKey(String fingerprint) {
        PGPSecretKeyRing secret = keyStore.findSecretKey(fingerprint);
        if (secret == null) {
            throw new ToolExecutionException("No secret key " + fingerprint + " in the BC private key store");
        }
        return armorKeyRing(secret);
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Looks up a user ID the key's holder bound and has not revoked, chosen as the user ID shown
     * for a verified signature is, never one a keyserver added to a copy; {@code null} when the
     * key is not in the store or binds none.
     */
    @Override
    public String lookupKeyUserId(String keyId) {
        BcKeyStore.KeyLookup found = keyStore.findPublicKey(keyId);
        if (found == null) {
            return null;
        }
        OpenPGPCertificate certificate = new OpenPGPCertificate(found.ring(),
                api.getImplementation(), VERIFICATION_POLICY);
        return displayedUserId(certificate, keyId, new Date());
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Supports key material, looked up by fingerprint, and identities carrying an email
     * address, looked up by the address in local stores. Looking a key up by address finds
     * candidates; it proves nothing about who owns the address.
     */
    @Override
    public boolean canInspect(Credential credential) {
        return credential instanceof KeyCredential || emailOf(credential) != null;
    }

    private static String emailOf(Credential credential) {
        return credential instanceof IdentityCredential identity
                ? identity.attribute(IdentityCredential.EMAIL)
                : null;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Queries local stores (the GnuPG keyring, cert-d, keys fetched this session) and, for
     * fingerprint credentials, each configured HKP keyserver independently.
     * Each source produces a separate {@link SignerSourceResult} with full key
     * metadata when found.
     */
    @Override
    public List<SignerSourceResult> inspect(Credential credential) {
        List<SignerSourceResult> results = new ArrayList<>();

        inspectLocalStores(credential, results);

        if (credential instanceof KeyCredential fc && fetcher != null) {
            String keyId = fc.fingerprint();
            for (String keyserver : fetcher.keyservers()) {
                PGPPublicKeyRing keyRing = fetcher.downloadCopy(keyId, keyserver);
                if (keyRing != null) {
                    results.add(new SignerSourceResult(SOURCE_HKP, keyserver, true,
                            extractKeyInfo(keyRing)));
                } else {
                    results.add(new SignerSourceResult(SOURCE_HKP, keyserver, false, null));
                }
            }
        }

        return results;
    }

    private void inspectLocalStores(Credential credential, List<SignerSourceResult> results) {
        String fingerprint = credential instanceof KeyCredential key ? key.fingerprint() : null;
        for (BcKeyStore.KeyLookup lookup : keyStore.inspect(fingerprint, emailOf(credential))) {
            String label = lookup.source().displayName();
            results.add(lookup.ring() != null
                    ? new SignerSourceResult(SOURCE_LOCAL, label, true, extractKeyInfo(lookup.ring()))
                    : new SignerSourceResult(SOURCE_LOCAL, label, false, null));
        }
    }

    private SignerInspectionResult extractKeyInfo(PGPPublicKeyRing keyRing) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        String fingerprint = KeyRingFiles.hex(primaryKey.getFingerprint());
        int version = primaryKey.getVersion();
        String algorithm = resolveAlgorithm(primaryKey.getAlgorithm());
        int bitStrength = primaryKey.getBitStrength();
        Instant creationDate = primaryKey.getCreationTime().toInstant();

        Instant expirationDate = null;
        long validSeconds = primaryKey.getValidSeconds();
        if (validSeconds > 0) {
            expirationDate = creationDate.plusSeconds(validSeconds);
        }

        List<String> userIds;
        Iterator<String> uidIt = primaryKey.getUserIDs();
        if (uidIt.hasNext()) {
            userIds = new ArrayList<>();
            do {
                userIds.add(uidIt.next());
            } while (uidIt.hasNext());
        } else {
            userIds = List.of();
        }

        List<SubkeyInfo> subkeys;
        Iterator<PGPPublicKey> keyIt = keyRing.getPublicKeys();
        keyIt.next(); // skip primary
        if (keyIt.hasNext()) {
            subkeys = new ArrayList<>();
            do {
                PGPPublicKey subkey = keyIt.next();
                String subFp = KeyRingFiles.hex(subkey.getFingerprint());
                String subAlgo = resolveAlgorithm(subkey.getAlgorithm());
                Set<String> caps = extractKeyCapabilities(subkey);
                subkeys.add(new SubkeyInfo(subFp, subAlgo, subkey.getBitStrength(), caps));
            } while (keyIt.hasNext());
        } else {
            subkeys = List.of();
        }

        return new SignerInspectionResult(fingerprint, version, algorithm, bitStrength,
                creationDate, expirationDate, userIds, subkeys);
    }

    private Set<String> extractKeyCapabilities(PGPPublicKey key) {
        Iterator<PGPSignature> sigs = key.getSignatures();
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
            if (hashed == null)
                continue;
            int flags = hashed.getKeyFlags();
            if (flags == 0)
                continue;
            Set<String> caps = new LinkedHashSet<>(4);
            if ((flags & KeyFlags.CERTIFY_OTHER) != 0)
                caps.add("certify");
            if ((flags & KeyFlags.SIGN_DATA) != 0)
                caps.add("sign");
            if ((flags & KeyFlags.ENCRYPT_COMMS) != 0 || (flags & KeyFlags.ENCRYPT_STORAGE) != 0)
                caps.add("encrypt");
            if ((flags & KeyFlags.AUTHENTICATION) != 0)
                caps.add("authenticate");
            return caps;
        }
        return Set.of();
    }

    // --- Verification internals ---

    /**
     * Verifies a single OpenPGP signature block against an artifact.
     */
    private OpenPgpVerifyResult verifyOpenPgpClaim(Path artifactFile, OpenPgpClaim opgu) {
        int version = opgu.packetVersion();
        String fingerprint = opgu.issuerFingerprint();
        String algorithm = resolveAlgorithm(opgu.algorithmId());

        if (fingerprint == null) {
            fingerprint = extractKeyIdFromSignature(opgu);
        }
        if (fingerprint == null) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED, null, algorithm, version, null,
                    null);
        }

        BcKeyStore.PublicKeySearch search = certificateFor(fingerprint);
        BcKeyStore.KeyLookup found = search.found();
        if (found == null) {
            return keyNotFound(opgu, fingerprint, algorithm, version, unreadableCopy(search, fingerprint));
        }

        return verifySignature(artifactFile, opgu, found, version, fingerprint, algorithm);
    }

    /**
     * The copy of a key that could not be read: one in a store, else one a keyserver served.
     */
    private UnreadableCertificate unreadableCopy(BcKeyStore.PublicKeySearch search, String fingerprint) {
        if (search.unreadable() != null) {
            return search.unreadable();
        }
        return fetcher != null ? fetcher.unreadableCopyOf(fingerprint) : null;
    }

    /**
     * Reports a key no store holds a readable copy of.
     *
     * <p>
     * A copy of the key that could not be read decides the reason: one using an algorithm
     * Bouncy Castle does not implement is {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}, so
     * that a tool implementing it can still answer; a damaged one is
     * {@link IndeterminateReason#KEY_UNAVAILABLE}, as another copy may serve. Without one, the
     * key is missing.
     *
     * @param unreadable a copy of the key that could not be read, or {@code null}
     */
    private OpenPgpVerifyResult keyNotFound(OpenPgpClaim opgu, String fingerprint, String algorithm,
            int version, UnreadableCertificate unreadable) {
        if (unreadable == null) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, null,
                    algorithm, version, fingerprint, fingerprint).withDetail(notFoundDetail(opgu));
        }
        return switch (unreadable.cause()) {
            case UNKNOWN_ALGORITHM -> OpenPgpVerifyResult.indeterminate(
                    IndeterminateReason.UNSUPPORTED_ALGORITHM, null, algorithm, version, fingerprint,
                    fingerprint)
                    .withDetail("Bouncy Castle cannot read the copy from "
                            + where(unreadable.source()) + ": " + unreadable.message());
            case DAMAGED -> OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, null,
                    algorithm, version, fingerprint, fingerprint)
                    .withDetail("the copy from " + where(unreadable.source()) + " cannot be read: "
                            + unreadable.message());
        };
    }

    /**
     * Names where a copy of a key came from, for a detail: the store's location or the
     * keyserver's URL, else the kind of source.
     */
    private static String where(TrustRootRef source) {
        return source.identifier() != null ? source.identifier() : source.kind();
    }

    /**
     * Says why no copy of the key was found. A result citing a missing key is reported only when
     * fetching it failed or was not attempted, so a fetcher means the keyservers were asked;
     * keys are fetched by full fingerprint, never by a 64-bit key ID. Keyservers that could not
     * answer are named with what happened, as the key may be on them.
     */
    private String notFoundDetail(OpenPgpClaim opgu) {
        if (opgu.issuerFingerprint() == null) {
            return "the signature names only a key ID, which is not looked up on keyservers";
        }
        if (fetcher == null) {
            return "no local key store has it, and key fetching is off";
        }
        Map<String, String> unanswered = fetcher.unansweredServers(opgu.issuerFingerprint());
        if (unanswered.isEmpty()) {
            return "no local key store or configured keyserver has it";
        }
        String causes = unanswered.entrySet().stream()
                .map(server -> server.getKey() + " " + server.getValue())
                .collect(Collectors.joining("; ", " (", ")"));
        return unanswered.size() == fetcher.keyservers().size()
                ? "no local key store has it and no configured keyserver could be asked" + causes
                : "no local key store or configured keyserver that answered has it" + causes;
    }

    private String extractKeyIdFromSignature(OpenPgpClaim opgu) {
        try {
            byte[] sigBytes = AscCombiner.dearmor(opgu.armoredBlock());
            PGPSignature sig = parseSignature(sigBytes);
            if (sig != null && sig.getKeyID() != 0) {
                return String.format("%016X", sig.getKeyID());
            }
        } catch (Exception e) {
            // unable to extract key ID
        }
        return null;
    }

    /**
     * Performs the cryptographic signature verification.
     */
    private OpenPgpVerifyResult verifySignature(Path artifactFile, OpenPgpClaim opgu,
            BcKeyStore.KeyLookup found, int version, String fingerprint,
            String algorithm) {
        try {
            PGPPublicKeyRing pubKeyRing = bindingViewOf(found.ring());
            byte[] sigBytes = AscCombiner.dearmor(opgu.armoredBlock());
            PGPSignature signature = parseSignature(sigBytes);
            if (signature == null) {
                return OpenPgpVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED, null,
                        algorithm, version, fingerprint, fingerprint);
            }
            OpenPGPCertificate certificate = new OpenPGPCertificate(pubKeyRing,
                    api.getImplementation(), VERIFICATION_POLICY);
            OpenPGPCertificate unfiltered = new OpenPGPCertificate(found.ring(),
                    api.getImplementation(), VERIFICATION_POLICY);
            String userId = displayedUserId(unfiltered, fingerprint, signature.getCreationTime());
            if (findVerificationKey(pubKeyRing, signature) == null) {
                return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, userId, algorithm, version,
                        fingerprint, fingerprint).withDetail("the certificate found does not contain the signing key");
            }
            OpenPGPDocumentSignature document = verifyAgainst(certificate, signature, artifactFile);
            if (document == null || document.getIssuer() == null || !document.isTestedCorrect()) {
                return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint, fingerprint)
                        .withDetail("the artifact does not match the signature");
            }
            if (!document.isValid(VERIFICATION_POLICY)) {
                return keyNotValid(certificate, document, signature, version, fingerprint, algorithm, userId,
                        found.source());
            }
            PGPPublicKey signingKey = document.getIssuer().getPGPPublicKey();
            return OpenPgpVerifyResult.verified(userId, algorithm, version, fingerprint, fingerprint)
                    .withKeyFingerprints(KeyRingFiles.hex(signingKey.getFingerprint()),
                            primaryFingerprintOf(pubKeyRing, signingKey))
                    .withKeySource(found.source());
        } catch (Exception e) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.TOOL_UNAVAILABLE, null,
                    algorithm, version, fingerprint, fingerprint);
        }
    }

    /**
     * The certificate as Bouncy Castle must see it to decide whether the key is bound: with
     * only the user ID certifications that verify against the primary key, no user ID
     * certification revocations, and no user ID left without a verifying certification.
     *
     * <p>
     * Bouncy Castle 1.86 derives the primary key's binding from its first user ID alone and
     * takes a revocation without checking its type or signature. A first user ID that is unsigned,
     * certified by a forgery or revoked would so reject a key that GnuPG and Sequoia accept, and
     * a forged revocation would be read as one. The same holds for every key-level signature: a
     * key revocation, a direct-key signature, a subkey binding or a subkey revocation that does
     * not verify against the primary key, or that sits where its type does not belong, is a
     * forgery GnuPG and Sequoia ignore. It is removed here, so that a forged revocation is never
     * the attack signal and a forged expiry or set of key flags never makes a bound key
     * unavailable. The view is for this question only: a user ID revocation does not touch the
     * key, and a user ID is never a credential. The user ID to show is chosen from the
     * certificate unfiltered.
     */
    private static PGPPublicKeyRing bindingViewOf(PGPPublicKeyRing ring) {
        PGPPublicKey primary = ring.getPublicKey();
        List<byte[]> userIds = new ArrayList<>();
        primary.getRawUserIDs().forEachRemaining(userIds::add);
        PGPPublicKey view = primary;
        for (byte[] userId : userIds) {
            view = withVerifyingCertificationsOnly(view, primary, userId);
        }
        PGPPublicKeyRing filtered = PGPPublicKeyRing.insertPublicKey(ring,
                withVerifyingKeySignaturesOnly(view, primary));
        Iterator<PGPPublicKey> subkeys = ring.getPublicKeys();
        while (subkeys.hasNext()) {
            PGPPublicKey subkey = subkeys.next();
            if (!subkey.isMasterKey()) {
                filtered = PGPPublicKeyRing.insertPublicKey(filtered,
                        withVerifyingKeySignaturesOnly(subkey, primary));
            }
        }
        return filtered;
    }

    private static final List<Integer> KEY_SIGNATURE_TYPES = List.of(PGPSignature.KEY_REVOCATION,
            PGPSignature.DIRECT_KEY, PGPSignature.SUBKEY_BINDING, PGPSignature.SUBKEY_REVOCATION);

    private static PGPPublicKey withVerifyingKeySignaturesOnly(PGPPublicKey key, PGPPublicKey primary) {
        List<PGPSignature> signatures = new ArrayList<>();
        for (int type : KEY_SIGNATURE_TYPES) {
            key.getSignaturesOfType(type).forEachRemaining(signatures::add);
        }
        PGPPublicKey view = key;
        for (PGPSignature signature : signatures) {
            if (!isVerifyingKeySignature(signature, key, primary)) {
                view = PGPPublicKey.removeCertification(view, signature);
            }
        }
        return view;
    }

    private static boolean isVerifyingKeySignature(PGPSignature signature, PGPPublicKey key, PGPPublicKey primary) {
        boolean ofPrimary = key.isMasterKey();
        if (!belongsOn(signature.getSignatureType(), ofPrimary)) {
            return false;
        }
        try {
            signature.init(new BcPGPContentVerifierBuilderProvider(), primary);
            return ofPrimary ? signature.verifyCertification(primary)
                    : signature.verifyCertification(primary, key);
        } catch (PGPException | RuntimeException e) {
            return false;
        }
    }

    private static boolean belongsOn(int signatureType, boolean ofPrimary) {
        return ofPrimary
                ? signatureType == PGPSignature.KEY_REVOCATION || signatureType == PGPSignature.DIRECT_KEY
                : signatureType == PGPSignature.SUBKEY_REVOCATION || signatureType == PGPSignature.SUBKEY_BINDING;
    }

    private static PGPPublicKey withVerifyingCertificationsOnly(PGPPublicKey view, PGPPublicKey primary,
            byte[] userId) {
        List<PGPSignature> signatures = new ArrayList<>();
        primary.getSignaturesForID(userId).forEachRemaining(signatures::add);
        boolean certified = false;
        for (PGPSignature signature : signatures) {
            if (isVerifyingCertification(signature, userId, primary)) {
                certified = true;
            } else {
                view = PGPPublicKey.removeCertification(view, userId, signature);
            }
        }
        return certified ? view : PGPPublicKey.removeCertification(view, userId);
    }

    private static boolean isVerifyingCertification(PGPSignature signature, byte[] userId, PGPPublicKey primary) {
        if (signature.getSignatureType() == PGPSignature.CERTIFICATION_REVOCATION) {
            return false;
        }
        try {
            signature.init(new BcPGPContentVerifierBuilderProvider(), primary);
            return signature.verifyCertification(userId, primary);
        } catch (PGPException | RuntimeException e) {
            return false;
        }
    }

    /**
     * The user ID to show for a certificate: one its holder bound and has not revoked as of
     * the moment of signing.
     *
     * <p>
     * A user ID a keyserver added without the holder's self-signature is never shown, however
     * many copies carried it. Among the bound ones, a user ID a known directory's copy carried is
     * preferred, since the directory published it only after its owner proved the address; next
     * the primary user ID, then the first. A user ID that is not UTF-8 is never among them: Bouncy
     * Castle's certificate API drops it. A 64-bit key ID is first resolved to the full fingerprint
     * of the key it names in this certificate, so that it is shown the user ID a lookup by that
     * fingerprint is.
     *
     * @param keyId the fingerprint or 64-bit key ID the certificate was found by
     * @return the user ID, or {@code null} when the certificate binds none
     */
    private String displayedUserId(OpenPGPCertificate certificate, String keyId, Date signedAt) {
        String fingerprint = fingerprintIn(certificate.getPGPPublicKeyRing(), keyId);
        List<String> bound = certificate.getValidUserIds(signedAt).stream()
                .map(OpenPGPCertificate.OpenPGPUserId::getUserId)
                .filter(Objects::nonNull)
                .toList();
        if (bound.isEmpty()) {
            return null;
        }
        String directoryServed = directoryServedAmong(bound, fingerprint);
        if (directoryServed != null) {
            return directoryServed;
        }
        OpenPGPCertificate.OpenPGPUserId primaryUserId = certificate.getPrimaryUserId(signedAt);
        if (primaryUserId != null && bound.contains(primaryUserId.getUserId())) {
            return primaryUserId.getUserId();
        }
        return bound.get(0);
    }

    private static String fingerprintIn(PGPPublicKeyRing ring, String keyId) {
        Iterator<PGPPublicKey> keys = ring.getPublicKeys();
        while (keys.hasNext()) {
            String fingerprint = KeyRingFiles.hex(keys.next().getFingerprint());
            if (BcKeyStore.sameKey(fingerprint, keyId)) {
                return fingerprint;
            }
        }
        return keyId;
    }

    /**
     * The first of the bound user IDs a known directory's copy carried, in the order that copy
     * holds them, for the directories in the order their copies were kept; {@code null} when no
     * directory's copy carried one.
     */
    private String directoryServedAmong(List<String> bound, String fingerprint) {
        for (String keyserver : keyStore.keyserversServing(fingerprint)) {
            if (IssuerKind.directoryServing(keyserver) == null) {
                continue;
            }
            for (String userId : keyStore.userIdsServedBy(fingerprint, keyserver)) {
                if (bound.contains(userId)) {
                    return userId;
                }
            }
        }
        return null;
    }

    /**
     * Explains a signature that is cryptographically correct but whose key is not valid.
     *
     * <p>
     * Only a key that was revoked or had expired when it signed makes the signature
     * {@link ClaimOutcome#FAILED}. Otherwise the bytes are what the key signed, and what
     * is missing is a key that can be trusted to have made them: an algorithm the verification
     * policy rejects is {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}, and any other key the
     * certificate does not bind is {@link IndeterminateReason#KEY_UNAVAILABLE} — one served
     * without its self-signatures, as keys.openpgp.org serves a key whose owner never verified an
     * address, where a fuller copy may resolve it; one whose self-signature covers a user ID
     * that is not UTF-8, which Bouncy Castle's certificate API drops although GnuPG and Sequoia
     * use it; and one whose self-signatures do not verify, which GnuPG and Sequoia also refuse
     * to use rather than report as an attack (ADR-009).
     */
    private OpenPgpVerifyResult keyNotValid(OpenPGPCertificate certificate,
            OpenPGPDocumentSignature document, PGPSignature signature, int version,
            String fingerprint, String algorithm, String userId, TrustRootRef source) {
        Date signedAt = signature.getCreationTime();
        OpenPGPCertificate.OpenPGPComponentKey issuer = document.getIssuer();
        OpenPGPCertificate.OpenPGPPrimaryKey primary = certificate.getPrimaryKey();
        Optional<String> failure = failureDetail(primary, signedAt).or(() -> failureDetail(issuer, signedAt));
        if (failure.isPresent()) {
            return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint, fingerprint)
                    .withDetail(failure.get());
        }
        if (!algorithmsAccepted(signature, issuer.getPGPPublicKey())) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM, userId,
                    algorithm, version, fingerprint, fingerprint);
        }
        List<PGPSignature> selfSignatures = selfSignatures(primary.getPGPPublicKey(),
                issuer.getPGPPublicKey());
        if (selfSignatures.isEmpty()) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, userId,
                    algorithm, version, fingerprint, fingerprint)
                    .withDetail("the copy from " + where(source) + " carries no self-signature binding the key");
        }
        if (selfSignatures.stream().anyMatch(BcRunner::rejectedByPolicy)) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM, userId,
                    algorithm, version, fingerprint, fingerprint);
        }
        return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, userId,
                algorithm, version, fingerprint, fingerprint)
                .withDetail(hasUndecodableUserId(primary.getPGPPublicKey())
                        ? "its user ID is not valid UTF-8, which Bouncy Castle cannot read"
                        : "its self-signatures do not bind it");
    }

    private static boolean hasUndecodableUserId(PGPPublicKey primary) {
        Iterator<byte[]> userIds = primary.getRawUserIDs();
        while (userIds.hasNext()) {
            try {
                StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(userIds.next()));
            } catch (CharacterCodingException e) {
                return true;
            }
        }
        return false;
    }

    /**
     * Says why a key was revoked or had expired when it signed, or nothing when it was neither.
     * The certificate passed is the binding view, which holds only the revocations that verify,
     * so one a keyserver made up is never reported; the revocation's provenance comes from the
     * copies the store kept.
     */
    private Optional<String> failureDetail(OpenPGPCertificate.OpenPGPComponentKey key, Date at) {
        OpenPGPCertificate.OpenPGPComponentSignature revocation = key.getRevocation(at);
        if (revocation != null) {
            return Optional.of(revokedDetail(key, revocation));
        }
        Date expiry = key.getKeyExpirationDateAt(at);
        return expiry != null && !expiry.after(at)
                ? Optional.of("key expired on " + dateOf(expiry) + ", before it signed")
                : Optional.empty();
    }

    private String revokedDetail(OpenPGPCertificate.OpenPGPComponentKey key,
            OpenPGPCertificate.OpenPGPComponentSignature revocation) {
        PGPSignature signature = revocation.getSignature();
        String detail = "key revoked as " + revocationReason(signature) + " on "
                + dateOf(revocation.getCreationTime());
        List<String> servers = keyStore.revocationServedBy(KeyRingFiles.hex(key.getPGPPublicKey().getFingerprint()),
                signature);
        return servers.isEmpty() ? detail : detail + "; revocation served by " + String.join(", ", servers);
    }

    private static String revocationReason(PGPSignature revocation) {
        RevocationReason reason = revocation.getHashedSubPackets().getRevocationReason();
        if (reason == null) {
            return "no reason given";
        }
        return switch (reason.getRevocationReason()) {
            case RevocationReasonTags.KEY_COMPROMISED -> "compromised";
            case RevocationReasonTags.KEY_SUPERSEDED -> "superseded";
            case RevocationReasonTags.KEY_RETIRED -> "retired";
            default -> "no reason given";
        };
    }

    private static String dateOf(Date date) {
        return date.toInstant().atZone(ZoneOffset.UTC).toLocalDate().toString();
    }

    private static boolean algorithmsAccepted(PGPSignature signature, PGPPublicKey signingKey) {
        return VERIFICATION_POLICY.isAcceptableDocumentSignatureHashAlgorithm(
                signature.getHashAlgorithm(), signature.getCreationTime())
                && VERIFICATION_POLICY.isAcceptablePublicKeyStrength(signingKey.getAlgorithm(),
                        signingKey.getBitStrength());
    }

    /**
     * The self-signatures that could bind the signing key: the primary key's user ID
     * certifications and direct-key signatures, and for a subkey its binding signatures, all
     * issued by the primary key. A subkey without a binding has none. Their validity is not
     * judged here.
     */
    private static List<PGPSignature> selfSignatures(PGPPublicKey primary, PGPPublicKey signingKey) {
        List<PGPSignature> found = signaturesBy(primary, primary, candidate -> candidate.isCertification()
                || candidate.getSignatureType() == PGPSignature.DIRECT_KEY);
        if (signingKey.getKeyID() == primary.getKeyID()) {
            return found;
        }
        List<PGPSignature> bindings = signaturesBy(signingKey, primary,
                candidate -> candidate.getSignatureType() == PGPSignature.SUBKEY_BINDING);
        if (found.isEmpty() || bindings.isEmpty()) {
            return List.of();
        }
        found.addAll(bindings);
        return found;
    }

    private static List<PGPSignature> signaturesBy(PGPPublicKey key, PGPPublicKey issuer,
            Predicate<PGPSignature> kind) {
        List<PGPSignature> found = new ArrayList<>();
        Iterator<PGPSignature> signatures = key.getSignatures();
        while (signatures.hasNext()) {
            PGPSignature candidate = signatures.next();
            if (candidate.getKeyID() == issuer.getKeyID() && kind.test(candidate)) {
                found.add(candidate);
            }
        }
        return found;
    }

    private static boolean rejectedByPolicy(PGPSignature selfSignature) {
        return !VERIFICATION_POLICY.isAcceptableCertificationSignatureHashAlgorithm(
                selfSignature.getHashAlgorithm(), selfSignature.getCreationTime());
    }

    /**
     * Verifies a detached signature with Bouncy Castle's high-level API, which judges the
     * signature in the context of its certificate rather than of one key.
     *
     * <p>
     * A signature is valid only when it is cryptographically correct and the key that made it
     * was, at the signature's creation time, a component of the certificate: the primary key,
     * or a subkey whose binding signature by that primary verifies, which carries the signing
     * flag and, for a signing subkey, a valid back-signature (cross-certification) by the
     * subkey itself — and neither revoked nor expired, with the primary key's expiry applying
     * to the whole certificate. Judging at creation time keeps a verdict stable after a key
     * expires. Without these checks, a subkey attached to someone else's primary key would
     * prove that primary's fingerprint.
     *
     * @return the verified signature, or {@code null} when the processor attributed none
     */
    private OpenPGPDocumentSignature verifyAgainst(OpenPGPCertificate certificate,
            PGPSignature signature, Path artifactFile) throws IOException {
        OpenPGPDetachedSignatureProcessor processor = new OpenPGPDetachedSignatureProcessor(
                api.getImplementation(), VERIFICATION_POLICY)
                .addVerificationCertificate(certificate)
                .addSignature(signature);
        try (InputStream in = Files.newInputStream(artifactFile)) {
            List<OpenPGPDocumentSignature> signatures = processor.process(in);
            return signatures.isEmpty() ? null : signatures.get(0);
        }
    }

    /**
     * Returns the certificate's primary fingerprint when the verifying key is a subkey.
     */
    private static String primaryFingerprintOf(PGPPublicKeyRing ring, PGPPublicKey verifyKey) {
        PGPPublicKey primary = ring.getPublicKey();
        return primary == null || primary.getKeyID() == verifyKey.getKeyID()
                ? null
                : KeyRingFiles.hex(primary.getFingerprint());
    }

    /**
     * Parses a PGP signature from raw packet bytes.
     */
    private PGPSignature parseSignature(byte[] sigBytes) throws IOException {
        BcPGPObjectFactory factory = new BcPGPObjectFactory(sigBytes);
        Object obj = factory.nextObject();
        if (obj instanceof PGPSignatureList sigList && !sigList.isEmpty()) {
            return sigList.get(0);
        }
        return null;
    }

    /**
     * Finds the public key that should verify this signature.
     */
    private PGPPublicKey findVerificationKey(PGPPublicKeyRing keyRing, PGPSignature signature) {
        long sigKeyId = signature.getKeyID();
        PGPPublicKey key = keyRing.getPublicKey(sigKeyId);
        if (key != null) {
            return key;
        }
        var keys = keyRing.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey candidate = keys.next();
            if (candidate.getKeyID() == sigKeyId) {
                return candidate;
            }
        }
        return null;
    }

    /**
     * Resolves an algorithm ID to a human-readable name.
     */
    private String resolveAlgorithm(int algoId) {
        String name = Algorithms.algorithmName(algoId);
        if (name == null && algoId >= 0) {
            return "unknown(" + algoId + ")";
        }
        return name;
    }

    /**
     * Picks the certificate to verify a signature with: the one the key store holds for the key
     * the signature names, else the certificate of the key this runner has signed with.
     * <p>
     * A key loaded from {@code SIGMUND_BC_SIGNING_KEY} or a {@code tsk-file} is in no store, yet
     * the runner must verify its own signatures, as signing does when {@code signing.signer}
     * asserts who signs. The own certificate is available only after this runner has signed, and
     * is used only when no store holds the key: every other key is found in the stores as
     * before. Choosing it decides only which public key is tried — the signature is still
     * verified cryptographically against it. Its source is unknown, since no store holds it.
     *
     * @param fingerprint the fingerprint or key ID the signature names
     * @return the certificate and its source, or, when neither holds it, the copies that could
     *         not be read
     */
    private BcKeyStore.PublicKeySearch certificateFor(String fingerprint) {
        BcKeyStore.PublicKeySearch search = keyStore.searchPublicKey(fingerprint);
        if (search.found() != null) {
            return search;
        }
        for (PGPPublicKeyRing own : signingCertificates.values()) {
            if (BcKeyStore.matchesFingerprint(own, fingerprint)) {
                return new BcKeyStore.PublicKeySearch(new BcKeyStore.KeyLookup(TrustRootRef.unknown(), own), null);
            }
        }
        return search;
    }

    /**
     * Returns the certificate of a secret key: its public keys with their signatures.
     */
    private static PGPPublicKeyRing certificateOf(PGPSecretKeyRing secretKeyRing) {
        List<PGPPublicKey> publicKeys = new ArrayList<>();
        secretKeyRing.getPublicKeys().forEachRemaining(publicKeys::add);
        return new PGPPublicKeyRing(publicKeys);
    }

    // --- Signing internals ---

    /**
     * Loads the secret key ring to sign with: the TSK when one is configured, else the named
     * key {@code key} selects.
     */
    private PGPSecretKeyRing loadSigningKey(SigningInfo key) throws IOException, PGPException {
        if (tskBytes != null || tskFile != null) {
            return loadOwnKey();
        }
        String fingerprint = SigningKeys.requireListed(NAME, signingFingerprints, key);
        return loadNamedKey(fingerprint);
    }

    /**
     * Loads the configured TSK, from key material when given, else from the TSK file.
     */
    private PGPSecretKeyRing loadOwnKey() throws IOException, PGPException {
        return tskBytes != null ? loadTskBytes(tskBytes) : loadTskFile(tskFile);
    }

    /**
     * Loads a named key from the key store.
     */
    private PGPSecretKeyRing loadNamedKey(String fingerprint) {
        PGPSecretKeyRing ring = keyStore.findSecretKey(fingerprint);
        if (ring == null) {
            throw new ToolExecutionException("Signing key not found: " + fingerprint);
        }
        return ring;
    }

    /**
     * Loads a transferable secret key from a file.
     */
    private PGPSecretKeyRing loadTskFile(Path file) throws IOException, PGPException {
        try (InputStream in = Files.newInputStream(file);
                InputStream decoded = PGPUtil.getDecoderStream(in)) {
            return new PGPSecretKeyRing(decoded, new BcKeyFingerprintCalculator());
        }
    }

    private PGPSecretKeyRing loadTskBytes(byte[] bytes) throws IOException, PGPException {
        try (InputStream in = new ByteArrayInputStream(bytes);
                InputStream decoded = PGPUtil.getDecoderStream(in)) {
            return new PGPSecretKeyRing(decoded, new BcKeyFingerprintCalculator());
        }
    }

    /**
     * Signs an artifact with the given secret key ring.
     */
    private SignResult signWithKey(Path artifactFile, Path outputSig,
            PGPSecretKeyRing secretKeyRing) throws IOException, PGPException {
        PGPSecretKey signingKey = findSigningSecretKey(secretKeyRing);
        String primaryFingerprint = KeyRingFiles.hex(
                secretKeyRing.getPublicKey().getFingerprint());
        PGPPrivateKey privateKey = extractPrivateKey(signingKey, primaryFingerprint);
        int hashAlgo = HashAlgorithmTags.SHA512;

        // Use constructor that accepts signing key to auto-detect signature version
        // (v6 keys must produce v6 signatures, v4 keys produce v4 signatures)
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(
                        signingKey.getPublicKey().getAlgorithm(), hashAlgo),
                signingKey.getPublicKey());

        // Add issuer fingerprint subpacket for proper verification
        PGPSignatureSubpacketGenerator subpacketGen = new PGPSignatureSubpacketGenerator();
        subpacketGen.setIssuerFingerprint(false, signingKey.getPublicKey());
        sigGen.setHashedSubpackets(subpacketGen.generate());

        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        try (InputStream in = Files.newInputStream(artifactFile)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) >= 0) {
                sigGen.update(buf, 0, len);
            }
        }

        PGPSignature signature = sigGen.generate();
        ByteArrayOutputStream rawOut = new ByteArrayOutputStream();
        signature.encode(rawOut);
        String armored = AscCombiner.armor(rawOut.toByteArray());
        Files.writeString(outputSig, armored);

        String algoName = Algorithms.algorithmName(signingKey.getPublicKey().getAlgorithm());
        return new SignResult(algoName != null ? algoName : "unknown");
    }

    /**
     * Finds the signing-capable secret key in the ring, preferring subkeys
     * over the primary key (which may be certify-only per key flags).
     */
    private PGPSecretKey findSigningSecretKey(PGPSecretKeyRing keyRing) {
        PGPSecretKey primary = null;
        var keys = keyRing.getSecretKeys();
        while (keys.hasNext()) {
            PGPSecretKey key = keys.next();
            if (key.isSigningKey()) {
                if (key.isMasterKey()) {
                    primary = key;
                } else {
                    return key;
                }
            }
        }
        if (primary != null) {
            return primary;
        }
        throw new ToolExecutionException("No signing-capable key found in the key ring");
    }

    /**
     * Extracts the private key, handling both encrypted and unencrypted keys.
     * Throws {@link PGPException} for all failure modes so that callers
     * (e.g. {@link #sign}) can wrap them uniformly via the existing catch blocks.
     *
     * @param secretKey the secret key to extract the private key from (may be a subkey)
     * @param primaryFingerprint the primary key's fingerprint, used to request the
     *        passphrase — must match the fingerprint used during encryption
     *        (see {@link #encryptKeyRing}), which is always the primary key's
     */
    private PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey,
            String primaryFingerprint) throws PGPException {
        if (secretKey.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithmTags.NULL) {
            return secretKey.extractPrivateKey(null);
        }
        if (passphraseProvider == null) {
            throw new PGPException(
                    "Key is passphrase-protected but no passphrase provider is configured. "
                            + "Set SIGMUND_BC_PASSPHRASE or provide a passphrase interactively.");
        }
        char[] passphrase = passphraseProvider.getPassphrase(primaryFingerprint);
        if (passphrase == null || passphrase.length == 0) {
            throw new PGPException("No passphrase provided for key " + primaryFingerprint);
        }
        try {
            return secretKey.extractPrivateKey(
                    new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                            .build(passphrase));
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    /**
     * Encrypts a secret key ring with a passphrase using AES-256 AEAD (OCB mode,
     * Argon2 S2K). Returns the original ring if no passphrase provider is configured.
     *
     * <p>
     * Each key in the ring is encrypted individually because v6 AEAD encryption
     * binds the ciphertext to the key's public key packet as associated data.
     * The ring-level {@code copyWithNewPassword} cannot do this — it applies a
     * single pre-built encryptor to every key.
     */
    private PGPSecretKeyRing encryptKeyRing(PGPSecretKeyRing keyRing, String fingerprint)
            throws PGPException {
        if (passphraseProvider == null) {
            return keyRing;
        }
        char[] passphrase = passphraseProvider.getPassphrase(fingerprint);
        if (passphrase == null || passphrase.length == 0) {
            return keyRing;
        }
        try {
            BcAEADSecretKeyEncryptorBuilder aeadBuilder = new BcAEADSecretKeyEncryptorBuilder(
                    AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256,
                    S2K.Argon2Params.memoryConstrainedParameters());

            List<PGPSecretKey> encryptedKeys = new ArrayList<>();
            for (var keys = keyRing.getSecretKeys(); keys.hasNext();) {
                PGPSecretKey sk = keys.next();
                encryptedKeys.add(PGPSecretKey.copyWithNewPassword(
                        sk, null,
                        aeadBuilder.build(passphrase, sk.getPublicKey().getPublicKeyPacket())));
            }
            return new PGPSecretKeyRing(encryptedKeys);
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    // --- Key generation internals ---

    /**
     * Returns the key packet version for a credential type.
     *
     * @param credentialType {@code pgp4}, {@code pgp6}, or {@code null} for {@code pgp4}
     * @return the version
     * @throws ToolExecutionException for any other type
     */
    private static int keyVersion(String credentialType) {
        if (credentialType == null || Credential.TYPE_PGP4.equals(credentialType)) {
            return PublicKeyPacket.VERSION_4;
        }
        if (Credential.TYPE_PGP6.equals(credentialType)) {
            return PublicKeyPacket.VERSION_6;
        }
        throw new ToolExecutionException("Unsupported credential type for bc keys: " + credentialType
                + " (expected " + Credential.TYPE_PGP4 + " or " + Credential.TYPE_PGP6 + ")");
    }

    /**
     * Generates a key of the given version using BC 1.85's high-level {@code BcOpenPGPApi}, for
     * Ed25519, Ed448 and RSA. ECDSA (NIST P-curves) falls back to JCA-based generation, which
     * produces v4 keys only.
     *
     * <p>
     * A v4 Ed25519 key uses the legacy EdDSA encoding: GnuPG 2.4 reads Ed25519 in v4 keys only
     * in that form, and rejects the RFC 9580 one as an invalid public key algorithm. Ed448 has
     * no v4 form GnuPG reads, so it is generated as v6 only.
     */
    private OpenPGPKey generateKeyInternal(String userId, String cipherSuite, int version) throws Exception {
        String suite = cipherSuite.toLowerCase();
        boolean v4 = version == PublicKeyPacket.VERSION_4;
        return switch (suite) {
            case "ed25519" -> v4
                    ? api.generateKey(version)
                            .withPrimaryKey(PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                            .addUserId(userId)
                            .addSigningSubkey(PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                            .build()
                    : api.generateKey(version).ed25519x25519Key(userId).addSigningSubkey().build();
            case "ed448" -> {
                if (v4) {
                    throw new ToolExecutionException("Cipher suite ed448 produces " + Credential.TYPE_PGP6
                            + " keys only: GnuPG reads no v4 Ed448 key; use ed25519 for a "
                            + Credential.TYPE_PGP4 + " key");
                }
                yield api.generateKey(version).ed448x448Key(userId).addSigningSubkey().build();
            }
            case "rsa4096" -> api.generateKey(version).singletonRSAKey(4096, userId).build();
            case "nistp256", "nistp384", "nistp521" -> generateECDSAKey(userId, suite, version);
            default -> throw new ToolExecutionException(
                    "Unsupported cipher suite: " + cipherSuite);
        };
    }

    private OpenPGPKey generateECDSAKey(String userId, String suite, int version) throws Exception {
        if (version != PublicKeyPacket.VERSION_4) {
            throw new ToolExecutionException("Cipher suite " + suite + " produces v4 keys only; use "
                    + Credential.TYPE_PGP4 + ", or ed25519, ed448 or rsa4096 for a v6 key");
        }
        String curve = switch (suite) {
            case "nistp256" -> "secp256r1";
            case "nistp384" -> "secp384r1";
            default -> "secp521r1";
        };
        return generateECDSAKeyFallback(userId, curve);
    }

    /**
     * Generates an ECDSA key using JCA-based BC API (fallback for NIST P-curves).
     * BC 1.85's {@code BcOpenPGPApi} does not provide ECDSA key generation.
     */
    private OpenPGPKey generateECDSAKeyFallback(String userId, String curveName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        kpg.initialize(new ECGenParameterSpec(curveName), new SecureRandom());

        // The key version is stated rather than defaulted: this fallback produces v4 keys,
        // which is what makes these NIST P-curve keys importable into GnuPG.
        PGPKeyPair keyPair = new JcaPGPKeyPair(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.ECDSA,
                kpg.generateKeyPair(),
                new Date());
        PGPSecretKeyRing secretRing = buildKeyRing(keyPair, userId);

        // Return wrapper for compatibility with OpenPGPKey interface
        return wrapAsOpenPGPKey(secretRing);
    }

    /**
     * Wraps a PGPSecretKeyRing in an OpenPGPKey interface for compatibility.
     */
    private OpenPGPKey wrapAsOpenPGPKey(PGPSecretKeyRing secretRing) {
        return new OpenPGPKey(secretRing, new org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation());
    }

    /**
     * Builds a PGP key ring from a key pair (used by ECDSA fallback).
     *
     * <p>
     * The self-signature states the key's capabilities explicitly. Implementations differ on
     * what an unflagged key may do: GnuPG and Bouncy Castle infer signing capability from the
     * key itself, while Sequoia refuses to verify with a key that does not say it can sign
     * ("key is not signing capable"). Stating the flags is what makes a key generated here
     * usable by every backend.
     */
    private PGPSecretKeyRing buildKeyRing(PGPKeyPair keyPair, String userId) throws PGPException {
        int hashAlgo = selectHashForKey(keyPair.getPublicKey());
        PGPSignatureSubpacketGenerator capabilities = new PGPSignatureSubpacketGenerator();
        capabilities.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                keyPair,
                userId,
                new JcaPGPDigestCalculatorProviderBuilder().build().get(hashAlgo),
                capabilities.generate(),
                null,
                new JcaPGPContentSignerBuilder(
                        keyPair.getPublicKey().getAlgorithm(), hashAlgo),
                new JcePBESecretKeyEncryptorBuilder(0).build(null));

        return keyRingGen.generateSecretKeyRing();
    }

    /**
     * Selects the appropriate hash algorithm for a public key's bit strength.
     */
    private int selectHashForKey(PGPPublicKey key) {
        int bitStrength = key.getBitStrength();
        if (bitStrength > 384) {
            return HashAlgorithmTags.SHA512;
        }
        if (bitStrength > 256) {
            return HashAlgorithmTags.SHA384;
        }
        return HashAlgorithmTags.SHA256;
    }

    /**
     * Armors a public key ring as an ASCII string.
     */
    private String armorKeyRing(PGPKeyRing keyRing) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
                keyRing.encode(armored);
            }
            return out.toString();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to armor key", e);
        }
    }
}
