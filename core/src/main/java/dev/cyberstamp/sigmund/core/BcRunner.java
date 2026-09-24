package dev.cyberstamp.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
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
class BcRunner implements SignatureTool, KeyGenerator, KeyImporter,
        CertExporter, SignerIdentityResolver, SignerInspection {

    private static final String NAME = "bc";

    private static final String SOURCE_LOCAL = "local";
    private static final String SOURCE_HKP = "hkp";
    private static final String SOURCE_GNUPG_PUBRING = "GnuPG pubring";
    private static final String SOURCE_CERT_D = "cert-d store";
    private static final String SOURCE_EPHEMERAL = "ephemeral cache";

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of(
            Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6);

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final BcOpenPGPApi api;
    private final BcKeyStore keyStore;
    private final String signingFingerprint;
    private final Path tskFile;
    private final byte[] tskBytes;
    private final PassphraseProvider passphraseProvider;
    private final OpenPgpSignatureFormat format;
    private final boolean resolveSigners;
    private final boolean importToKeyring;
    private final List<String> keyservers;
    private final KeyFetchCache fetchCache;
    private final HttpClient httpClient;

    /**
     * Creates a new BC runner without passphrase support or key fetching.
     *
     * @param keyStore the key store for key lookup and storage
     * @param signingFingerprint the fingerprint of the key to sign with, or {@code null}
     * @param tskFile the path to a TSK file for signing, or {@code null}
     */
    BcRunner(BcKeyStore keyStore, String signingFingerprint, Path tskFile) {
        this(keyStore, signingFingerprint, tskFile, null, null, false, false, List.of());
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
        this(keyStore, signingFingerprint, tskFile, null, passphraseProvider, false, false, List.of());
    }

    /**
     * Creates a new BC runner with full key fetching configuration.
     *
     * @param keyStore the key store for key lookup and storage
     * @param signingFingerprint the fingerprint of the key to sign with, or {@code null}
     * @param tskFile the path to a TSK file for signing, or {@code null}
     * @param tskBytes raw TSK key material (e.g. from an env var), or {@code null}
     * @param passphraseProvider provides passphrases for encrypted keys, or {@code null}
     * @param resolveSigners whether to fetch missing keys from keyservers
     * @param importToKeyring whether to persist fetched keys to disk (cert-d) or cache in memory
     * @param keyservers keyserver URLs to fetch from
     */
    BcRunner(BcKeyStore keyStore, String signingFingerprint, Path tskFile,
            byte[] tskBytes, PassphraseProvider passphraseProvider,
            boolean resolveSigners, boolean importToKeyring, List<String> keyservers) {
        this.api = new BcOpenPGPApi();
        this.keyStore = keyStore;
        this.signingFingerprint = signingFingerprint;
        this.tskFile = tskFile;
        this.tskBytes = tskBytes != null ? tskBytes.clone() : null;
        this.passphraseProvider = passphraseProvider;
        this.format = new OpenPgpSignatureFormat();
        this.resolveSigners = resolveSigners;
        this.importToKeyring = importToKeyring;
        this.keyservers = keyservers != null ? List.copyOf(keyservers) : List.of();
        this.fetchCache = new KeyFetchCache();
        this.httpClient = resolveSigners && !this.keyservers.isEmpty()
                ? HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build()
                : null;
    }

    @Override
    public String name() {
        return NAME;
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
     * Returns {@code true} if a signing fingerprint or TSK file was provided.
     */
    @Override
    public boolean canSign() {
        return signingFingerprint != null || tskFile != null || tskBytes != null;
    }

    @Override
    public List<SigningInfo> signingInfo() {
        if (!canSign()) {
            return List.of();
        }
        try {
            PGPSecretKeyRing ring = loadSigningKey();
            PGPPublicKey pub = ring.getPublicKey();
            String fp = BcKeyStore.bytesToHex(pub.getFingerprint());
            String algo = Algorithms.algorithmName(pub.getAlgorithm());
            String userId = keyStore.findPrimaryUserId(fp);
            int version = pub.getVersion();
            Set<String> types = version >= 6
                    ? Set.of(Credential.TYPE_OPENPGP_V6)
                    : Set.of(Credential.TYPE_OPENPGP_V4);
            return List.of(new SigningInfo(NAME, fp, algo, userId, types));
        } catch (IOException | PGPException e) {
            String fp = signingFingerprint != null ? signingFingerprint
                    : (tskFile != null ? tskFile.getFileName().toString()
                            : (tskBytes != null ? "(env var key)" : null));
            return List.of(new SigningInfo(NAME, fp, null, null, SUPPORTED_CREDENTIAL_TYPES));
        }
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
        return TrustRootRef.keyring(keyStore.certDHome());
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
     * Creates a detached ASCII-armored signature.
     *
     * @throws IllegalStateException if {@link #canSign()} is {@code false}
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig) {
        if (!canSign()) {
            throw new IllegalStateException("No signing key configured");
        }
        try {
            PGPSecretKeyRing secretKeyRing = loadSigningKey();
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
     * Generates a v6 key using BC 1.85's high-level {@code BcOpenPGPApi}.
     */
    @Override
    public String generateKey(String userId, String cipherSuite) {
        try {
            OpenPGPKey key = generateKeyInternal(userId, cipherSuite);
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
     * BC can always fetch ephemerally (in-memory) regardless of the
     * {@code importToKeyring} setting. Returns {@code true} when
     * {@code resolveSigners} is enabled and at least one keyserver is configured.
     */
    @Override
    public boolean canFetchKeys() {
        return resolveSigners && !keyservers.isEmpty();
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Short-circuits if the key is already in the local keystore (previously
     * fetched or pre-existing). Otherwise iterates configured keyservers,
     * checking the {@link KeyFetchCache} before each attempt. On success,
     * stores the key ephemerally (in-memory) or persistently (cert-d) based
     * on the {@code importToKeyring} flag. Connection-level failures (timeout,
     * refused) trip the per-keyserver circuit breaker. If the key is not found
     * on any healthy server, it is added to the negative cache to prevent
     * re-querying across artifacts.
     */
    @Override
    public boolean fetchKey(String keyId) {
        if (!canFetchKeys()) {
            return false;
        }
        if (!fetchCache.shouldAttemptKey(keyId)) {
            return false;
        }
        PGPPublicKeyRing existing = keyStore.findPublicKey(keyId);
        if (existing != null && hasUserIds(existing)) {
            return true;
        }
        boolean fetched = false;
        for (String keyserver : keyservers) {
            if (!fetchCache.shouldAttempt(keyserver, keyId)) {
                continue;
            }
            PGPPublicKeyRing ring = fetchFromHkpAndStore(keyId, keyserver);
            if (ring != null) {
                fetched = true;
                if (hasUserIds(ring)) {
                    return true;
                }
            }
        }
        if (!fetched) {
            fetchCache.recordKeyNotFound(keyId);
        }
        return fetched;
    }

    PGPPublicKeyRing fetchFromHkpAndStore(String keyId, String keyserver) {
        try {
            PGPPublicKeyRing keyRing = fetchKeyFromHkp(keyId, keyserver);
            if (keyRing == null) {
                return null;
            }
            if (importToKeyring) {
                keyStore.storeCert(keyRing);
            } else {
                keyStore.cacheEphemeral(keyRing);
            }
            fetchCache.recordSuccess(keyserver, keyId);
            return keyRing;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean hasUserIds(PGPPublicKeyRing ring) {
        return ring.getPublicKey().getUserIDs().hasNext();
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Exports the public certificate as an ASCII-armored string.
     */
    @Override
    public String exportCert(String fingerprint) {
        PGPPublicKeyRing keyRing = keyStore.findPublicKey(fingerprint);
        if (keyRing == null) {
            throw new ToolExecutionException("Certificate not found: " + fingerprint);
        }
        return armorKeyRing(keyRing);
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
     * Supports {@link FingerprintCredential} and {@link EmailCredential}.
     */
    @Override
    public boolean canInspect(Credential credential) {
        return credential instanceof FingerprintCredential
                || credential instanceof EmailCredential;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Queries local stores (GnuPG pubring, cert-d, ephemeral cache) and, for
     * fingerprint credentials, each configured HKP keyserver independently.
     * Each source produces a separate {@link SignerSourceResult} with full key
     * metadata when found.
     */
    @Override
    public List<SignerSourceResult> inspect(Credential credential) {
        List<SignerSourceResult> results = new ArrayList<>(3 + keyservers.size());

        inspectLocalStores(credential, results);

        if (credential instanceof FingerprintCredential fc && httpClient != null) {
            String keyId = fc.fingerprint();
            for (String keyserver : keyservers) {
                PGPPublicKeyRing keyRing = fetchKeyFromHkp(keyId, keyserver);
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
        if (keyStore.hasGnupgPubring()) {
            PGPPublicKeyRing key = null;
            if (credential instanceof FingerprintCredential fc) {
                key = keyStore.findInGnupg(fc.fingerprint());
            } else if (credential instanceof EmailCredential ec) {
                key = keyStore.findInGnupgByEmail(ec.email());
            }
            results.add(key != null
                    ? new SignerSourceResult(SOURCE_LOCAL, SOURCE_GNUPG_PUBRING, true, extractKeyInfo(key))
                    : new SignerSourceResult(SOURCE_LOCAL, SOURCE_GNUPG_PUBRING, false, null));
        }

        if (keyStore.hasCertD()) {
            PGPPublicKeyRing key = null;
            if (credential instanceof FingerprintCredential fc) {
                key = keyStore.findInCertDStore(fc.fingerprint());
            } else if (credential instanceof EmailCredential ec) {
                key = keyStore.findInCertDByEmail(ec.email());
            }
            results.add(key != null
                    ? new SignerSourceResult(SOURCE_LOCAL, SOURCE_CERT_D, true, extractKeyInfo(key))
                    : new SignerSourceResult(SOURCE_LOCAL, SOURCE_CERT_D, false, null));
        }

        PGPPublicKeyRing ephemeral = null;
        if (credential instanceof FingerprintCredential fc) {
            ephemeral = keyStore.findInEphemeralStore(fc.fingerprint());
        } else if (credential instanceof EmailCredential ec) {
            ephemeral = keyStore.findInEphemeralByEmail(ec.email());
        }
        if (ephemeral != null) {
            results.add(new SignerSourceResult(SOURCE_LOCAL, SOURCE_EPHEMERAL, true,
                    extractKeyInfo(ephemeral)));
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

        PGPPublicKeyRing pubKeyRing = keyStore.findPublicKey(fingerprint);
        if (pubKeyRing == null) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, null, algorithm, version, fingerprint,
                    fingerprint);
        }

        String userId = keyStore.findPrimaryUserId(fingerprint);
        return verifySignature(artifactFile, opgu, pubKeyRing, version,
                fingerprint, algorithm, userId);
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
            PGPPublicKeyRing pubKeyRing, int version, String fingerprint,
            String algorithm, String userId) {
        try {
            byte[] sigBytes = AscCombiner.dearmor(opgu.armoredBlock());
            PGPSignature signature = parseSignature(sigBytes);
            if (signature == null) {
                return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint, fingerprint);
            }

            PGPPublicKey verifyKey = findVerificationKey(pubKeyRing, signature);
            if (verifyKey == null) {
                return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, userId, algorithm, version,
                        fingerprint, fingerprint);
            }

            // Judged at the claim time, not now: a signature made while the key was valid
            // stays valid after the key expires, and one dated outside that window did not
            // come from a valid key however well the bytes verify.
            if (!KeyValidity.isValidAt(verifyKey, opgu.claimTime())) {
                return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint,
                        fingerprint);
            }

            boolean valid = verifyDetachedSignature(signature, verifyKey, artifactFile);
            return new OpenPgpVerifyResult(
                    valid ? ClaimOutcome.VERIFIED : ClaimOutcome.FAILED, null,
                    userId, algorithm, version, fingerprint, fingerprint);
        } catch (Exception e) {
            return OpenPgpVerifyResult.failed(userId, algorithm, version, fingerprint, fingerprint);
        }
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
     * Verifies a detached signature against an artifact file.
     */
    private boolean verifyDetachedSignature(PGPSignature signature,
            PGPPublicKey publicKey, Path artifactFile) throws IOException, PGPException {
        signature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
        try (InputStream in = Files.newInputStream(artifactFile)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) >= 0) {
                signature.update(buf, 0, len);
            }
        }
        return signature.verify();
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

    // --- Signing internals ---

    /**
     * Loads the secret key ring for signing.
     */
    private PGPSecretKeyRing loadSigningKey() throws IOException, PGPException {
        if (tskBytes != null) {
            return loadTskBytes(tskBytes);
        }
        if (tskFile != null) {
            return loadTskFile(tskFile);
        }
        PGPSecretKeyRing ring = keyStore.findSecretKey(signingFingerprint);
        if (ring == null) {
            throw new ToolExecutionException("Signing key not found: " + signingFingerprint);
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
     * Generates a key using BC 1.85's high-level {@code BcOpenPGPApi}.
     * Produces v6 keys for Ed25519, Ed448, and RSA.
     * Falls back to JCA-based generation for ECDSA (NIST P-curves).
     */
    private OpenPGPKey generateKeyInternal(String userId, String cipherSuite) throws Exception {
        return switch (cipherSuite.toLowerCase()) {
            case "ed25519" -> api.generateKey().ed25519x25519Key(userId).addSigningSubkey().build();
            case "ed448" -> api.generateKey().ed448x448Key(userId).addSigningSubkey().build();
            case "rsa4096" -> api.generateKey().singletonRSAKey(4096, userId).build();
            case "nistp256" -> generateECDSAKeyFallback(userId, "secp256r1");
            case "nistp384" -> generateECDSAKeyFallback(userId, "secp384r1");
            case "nistp521" -> generateECDSAKeyFallback(userId, "secp521r1");
            default -> throw new ToolExecutionException(
                    "Unsupported cipher suite: " + cipherSuite);
        };
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

    // --- HKP key import internals ---

    /**
     * Fetches a public key from an HKP keyserver.
     * <p>
     * Distinguishes connection-level failures (which trip the circuit breaker)
     * from HTTP-level errors (key not found on a healthy server).
     */
    private PGPPublicKeyRing fetchKeyFromHkp(String keyId, String keyserver) {
        String url = buildHkpUrl(keyserver, keyId);
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                return null;
            }
            try (InputStream in = PGPUtil.getDecoderStream(
                    new ByteArrayInputStream(response.body()))) {
                return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
            }
        } catch (HttpTimeoutException | ConnectException e) {
            fetchCache.recordConnectionFailure(keyserver);
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Builds the HKP lookup URL for the given keyserver and key ID.
     */
    private String buildHkpUrl(String keyserver, String keyId) {
        String base;
        if (keyserver.startsWith("hkps://")) {
            base = "https://" + keyserver.substring(7);
        } else if (keyserver.startsWith("hkp://")) {
            base = "http://" + keyserver.substring(6);
        } else if (keyserver.startsWith("https://") || keyserver.startsWith("http://")) {
            base = keyserver;
        } else {
            base = "https://" + keyserver;
        }
        if (!base.endsWith("/")) {
            base += "/";
        }
        return base + "pks/lookup?op=get&options=mr&search=0x" + keyId;
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
