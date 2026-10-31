package dev.cyberstamp.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
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
class BcRunner implements AutoCloseable, SignatureTool, KeyGenerator, KeyImporter,
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

    private SigningInfo describe(PGPSecretKeyRing ring) {
        PGPPublicKey pub = ring.getPublicKey();
        String fp = BcKeyStore.bytesToHex(pub.getFingerprint());
        String type = pub.getVersion() >= 6 ? Credential.TYPE_PGP6 : Credential.TYPE_PGP4;
        return new SigningInfo(NAME, fp, Algorithms.algorithmName(pub.getAlgorithm()),
                keyStore.findPrimaryUserId(fp), type);
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
     * Accepts any {@link OpenPgpClaim} — handles all packet versions.
     */
    @Override
    public boolean canVerify(Claim claim) {
        return claim instanceof OpenPgpClaim;
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
            signingCertificates.put(BcKeyStore.bytesToHex(certificate.getPublicKey().getFingerprint()),
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
            String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
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
     * Looks up the primary user ID from the key store.
     */
    @Override
    public String lookupKeyUserId(String keyId) {
        return keyStore.findPrimaryUserId(keyId);
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
                PGPPublicKeyRing keyRing = fetcher.download(keyId, keyserver);
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
        String fingerprint = BcKeyStore.bytesToHex(primaryKey.getFingerprint());
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
                String subFp = BcKeyStore.bytesToHex(subkey.getFingerprint());
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

        BcKeyStore.KeyLookup found = certificateFor(fingerprint);
        if (found == null) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, null, algorithm, version, fingerprint,
                    fingerprint);
        }

        return verifySignature(artifactFile, opgu, found, version, fingerprint, algorithm,
                keyStore.primaryUserIdOf(found.ring()));
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
            String algorithm, String userId) {
        PGPPublicKeyRing pubKeyRing = found.ring();
        try {
            byte[] sigBytes = AscCombiner.dearmor(opgu.armoredBlock());
            PGPSignature signature = parseSignature(sigBytes);
            if (signature == null) {
                return OpenPgpVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED, userId,
                        algorithm, version, fingerprint, fingerprint);
            }
            if (findVerificationKey(pubKeyRing, signature) == null) {
                return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, userId, algorithm, version,
                        fingerprint, fingerprint);
            }

            OpenPGPCertificate certificate = new OpenPGPCertificate(pubKeyRing,
                    api.getImplementation(), VERIFICATION_POLICY);
            OpenPGPDocumentSignature document = verifyAgainst(certificate, signature, artifactFile);
            if (document == null || document.getIssuer() == null || !document.isTestedCorrect()) {
                return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint, fingerprint);
            }
            if (!document.isValid(VERIFICATION_POLICY)) {
                return keyNotValid(certificate, document, signature, version, fingerprint, algorithm, userId);
            }
            PGPPublicKey signingKey = document.getIssuer().getPGPPublicKey();
            return OpenPgpVerifyResult.verified(userId, algorithm, version, fingerprint, fingerprint)
                    .withKeyFingerprints(hex(signingKey.getFingerprint()),
                            primaryFingerprintOf(pubKeyRing, signingKey))
                    .withKeySource(found.source());
        } catch (Exception e) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.TOOL_UNAVAILABLE, userId,
                    algorithm, version, fingerprint, fingerprint);
        }
    }

    /**
     * Explains a signature that is cryptographically correct but whose key is not valid.
     *
     * <p>
     * Only a key that was revoked or had expired when it signed makes the signature
     * {@link ClaimOutcome#FAILED}. Otherwise the bytes are what the key signed, and what
     * is missing is a key that can be trusted to have made them: an algorithm the verification
     * policy rejects is {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}, and a certificate
     * that carries no self-signature binding the key — as keys.openpgp.org serves one whose
     * owner never verified an address — is {@link IndeterminateReason#KEY_UNAVAILABLE}, since
     * a fuller copy of the certificate may resolve it. Self-signatures that are present, use
     * acceptable algorithms and still do not bind the key are a broken or forged certificate,
     * which is {@code FAILED}.
     */
    private OpenPgpVerifyResult keyNotValid(OpenPGPCertificate certificate,
            OpenPGPDocumentSignature document, PGPSignature signature, int version,
            String fingerprint, String algorithm, String userId) {
        Date signedAt = signature.getCreationTime();
        OpenPGPCertificate.OpenPGPComponentKey issuer = document.getIssuer();
        OpenPGPCertificate.OpenPGPPrimaryKey primary = certificate.getPrimaryKey();
        if (revokedOrExpiredAt(primary, signedAt) || revokedOrExpiredAt(issuer, signedAt)) {
            return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint, fingerprint);
        }
        if (!algorithmsAccepted(signature, issuer.getPGPPublicKey())) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM, userId,
                    algorithm, version, fingerprint, fingerprint);
        }
        List<PGPSignature> selfSignatures = selfSignatures(primary.getPGPPublicKey(),
                issuer.getPGPPublicKey());
        if (selfSignatures.isEmpty()) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, userId,
                    algorithm, version, fingerprint, fingerprint);
        }
        if (selfSignatures.stream().anyMatch(BcRunner::rejectedByPolicy)) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM, userId,
                    algorithm, version, fingerprint, fingerprint);
        }
        return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint, fingerprint);
    }

    private static boolean revokedOrExpiredAt(OpenPGPCertificate.OpenPGPComponentKey key, Date at) {
        if (key.getRevocation(at) != null) {
            return true;
        }
        Date expiry = key.getKeyExpirationDateAt(at);
        return expiry != null && !expiry.after(at);
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
                : hex(primary.getFingerprint());
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().withUpperCase().formatHex(bytes);
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
     * @return the certificate and its source, or {@code null} when neither holds it
     */
    private BcKeyStore.KeyLookup certificateFor(String fingerprint) {
        BcKeyStore.KeyLookup found = keyStore.findPublicKey(fingerprint);
        if (found != null) {
            return found;
        }
        for (PGPPublicKeyRing own : signingCertificates.values()) {
            if (BcKeyStore.matchesFingerprint(own, fingerprint)) {
                return new BcKeyStore.KeyLookup(TrustRootRef.unknown(), own);
            }
        }
        return null;
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
        String primaryFingerprint = BcKeyStore.bytesToHex(
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
    private String armorKeyRing(PGPPublicKeyRing keyRing) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
                keyRing.encode(armored);
            }
            return out.toString();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to armor certificate", e);
        }
    }
}
