package io.github.cyberstamp.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
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
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
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
 * @see BcKeyStore
 */
public class BcRunner implements SignatureTool, KeyGenerator, KeyImporter,
        CertExporter, SignerIdentityResolver {

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of(
            Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6);

    private final BcOpenPGPApi api;
    private final BcKeyStore keyStore;
    private final String signingFingerprint;
    private final Path tskFile;
    private final OpenPgpSignatureFormat format;

    /**
     * Creates a new BC runner.
     *
     * @param keyStore the key store for key lookup and storage
     * @param signingFingerprint the fingerprint of the key to sign with, or {@code null}
     * @param tskFile the path to a TSK file for signing, or {@code null}
     */
    public BcRunner(BcKeyStore keyStore, String signingFingerprint, Path tskFile) {
        this.api = new BcOpenPGPApi();
        this.keyStore = keyStore;
        this.signingFingerprint = signingFingerprint;
        this.tskFile = tskFile;
        this.format = new OpenPgpSignatureFormat();
    }

    @Override
    public String name() {
        return "bc";
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
        return signingFingerprint != null || tskFile != null;
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
     * Accepts any {@link OpenPgpVerificationUnit} — handles all packet versions.
     */
    @Override
    public boolean canVerify(VerificationUnit unit) {
        return unit instanceof OpenPgpVerificationUnit;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Verifies a detached OpenPGP signature using Bouncy Castle.
     */
    @Override
    public VerifyResult verify(Path artifactFile, VerificationUnit unit) {
        if (!(unit instanceof OpenPgpVerificationUnit opgu)) {
            return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, -1, null, null);
        }
        return verifyOpenPgpUnit(artifactFile, opgu);
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
        if (result.verdict() != Verdict.PASS) {
            return List.of();
        }
        if (result instanceof OpenPgpVerifyResult opvr && opvr.fingerprint() != null) {
            String credType = opvr.version() < 6
                    ? Credential.TYPE_OPENPGP_V4
                    : Credential.TYPE_OPENPGP_V6;
            List<Credential> creds = new ArrayList<>(2);
            creds.add(new FingerprintCredential(credType, opvr.fingerprint()));
            String email = GpgRunner.extractEmail(result.signerDisplayName());
            if (email != null) {
                creds.add(new EmailCredential(email));
            }
            return List.copyOf(creds);
        }
        return List.of();
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
            keyStore.storeCert(publicKeyRing);
            keyStore.storeSecretKey(secretKeyRing);
            return BcKeyStore.bytesToHex(key.getFingerprint());
        } catch (Exception e) {
            throw new ToolExecutionException("Key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Fetches a key from an HKP/HKPS keyserver and stores it in cert-d.
     */
    @Override
    public boolean importKey(String keyId, String keyserver) {
        return fetchAndStore(keyId, keyserver, true);
    }

    /**
     * Fetches a key from a keyserver and caches it in memory without writing to disk.
     * <p>
     * The key is available for verification via {@link BcKeyStore#findPublicKey(String)}
     * for the lifetime of this JVM but is not persisted to the cert-d directory.
     */
    @Override
    public boolean fetchKeyEphemeral(String keyId, String keyserver) {
        return fetchAndStore(keyId, keyserver, false);
    }

    private boolean fetchAndStore(String keyId, String keyserver, boolean persistent) {
        try {
            PGPPublicKeyRing keyRing = fetchKeyFromHkp(keyId, keyserver);
            if (keyRing == null) {
                return false;
            }
            if (persistent) {
                keyStore.storeCert(keyRing);
            } else {
                keyStore.cacheEphemeral(keyRing);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
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

    // --- Verification internals ---

    /**
     * Verifies a single OpenPGP signature block against an artifact.
     */
    private OpenPgpVerifyResult verifyOpenPgpUnit(Path artifactFile, OpenPgpVerificationUnit opgu) {
        int version = opgu.packetVersion();
        String fingerprint = opgu.issuerFingerprint();
        String algorithm = resolveAlgorithm(opgu.algorithmId());

        if (fingerprint == null) {
            fingerprint = extractKeyIdFromSignature(opgu);
        }
        if (fingerprint == null) {
            return new OpenPgpVerifyResult(Verdict.SKIPPED, null, algorithm,
                    version, null, null);
        }

        PGPPublicKeyRing pubKeyRing = keyStore.findPublicKey(fingerprint);
        if (pubKeyRing == null) {
            return new OpenPgpVerifyResult(Verdict.NO_KEY, null, algorithm,
                    version, fingerprint, fingerprint);
        }

        String userId = keyStore.findPrimaryUserId(fingerprint);
        return verifySignature(artifactFile, opgu, pubKeyRing, version,
                fingerprint, algorithm, userId);
    }

    private String extractKeyIdFromSignature(OpenPgpVerificationUnit opgu) {
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
    private OpenPgpVerifyResult verifySignature(Path artifactFile, OpenPgpVerificationUnit opgu,
            PGPPublicKeyRing pubKeyRing, int version, String fingerprint,
            String algorithm, String userId) {
        try {
            byte[] sigBytes = AscCombiner.dearmor(opgu.armoredBlock());
            PGPSignature signature = parseSignature(sigBytes);
            if (signature == null) {
                return new OpenPgpVerifyResult(Verdict.FAIL, userId, algorithm,
                        version, fingerprint, fingerprint);
            }

            PGPPublicKey verifyKey = findVerificationKey(pubKeyRing, signature);
            if (verifyKey == null) {
                return new OpenPgpVerifyResult(Verdict.NO_KEY, userId, algorithm,
                        version, fingerprint, fingerprint);
            }

            boolean valid = verifyDetachedSignature(signature, verifyKey, artifactFile);
            return new OpenPgpVerifyResult(
                    valid ? Verdict.PASS : Verdict.FAIL,
                    userId, algorithm, version, fingerprint, fingerprint);
        } catch (Exception e) {
            return new OpenPgpVerifyResult(Verdict.FAIL, userId, algorithm,
                    version, fingerprint, fingerprint);
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

    /**
     * Signs an artifact with the given secret key ring.
     */
    private SignResult signWithKey(Path artifactFile, Path outputSig,
            PGPSecretKeyRing secretKeyRing) throws IOException, PGPException {
        PGPSecretKey signingKey = findSigningSecretKey(secretKeyRing);
        PGPPrivateKey privateKey = signingKey.extractPrivateKey(null);
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

        PGPKeyPair keyPair = new JcaPGPKeyPair(
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
     */
    private PGPSecretKeyRing buildKeyRing(PGPKeyPair keyPair, String userId) throws PGPException {
        int hashAlgo = selectHashForKey(keyPair.getPublicKey());
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                keyPair,
                userId,
                new JcaPGPDigestCalculatorProviderBuilder().build().get(hashAlgo),
                null,
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
     * Extracts public key ring from secret key ring (used by ECDSA fallback).
     */
    private PGPPublicKeyRing extractPublicKeyRing(PGPSecretKeyRing secretRing) {
        List<PGPPublicKey> pubKeys = new ArrayList<>();
        secretRing.getPublicKeys().forEachRemaining(pubKeys::add);
        return new PGPPublicKeyRing(pubKeys);
    }

    // --- HKP key import internals ---

    /**
     * Fetches a public key from an HKP keyserver.
     */
    private PGPPublicKeyRing fetchKeyFromHkp(String keyId, String keyserver) {
        String url = buildHkpUrl(keyserver, keyId);
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();
            HttpResponse<byte[]> response = client.send(request,
                    HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                return null;
            }
            try (InputStream in = PGPUtil.getDecoderStream(
                    new ByteArrayInputStream(response.body()))) {
                return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Builds the HKP lookup URL for the given keyserver and key ID.
     */
    private String buildHkpUrl(String keyserver, String keyId) {
        String base = keyserver.replaceFirst("^hkps://", "https://")
                .replaceFirst("^hkp://", "http://");
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
