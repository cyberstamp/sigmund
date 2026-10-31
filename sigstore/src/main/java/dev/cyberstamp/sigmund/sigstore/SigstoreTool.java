package dev.cyberstamp.sigmund.sigstore;

import dev.cyberstamp.sigmund.core.Claim;
import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import dev.cyberstamp.sigmund.core.SignResult;
import dev.cyberstamp.sigmund.core.SignatureFormat;
import dev.cyberstamp.sigmund.core.SignatureTool;
import dev.cyberstamp.sigmund.core.SigningInfo;
import dev.cyberstamp.sigmund.core.SigstoreClaim;
import dev.cyberstamp.sigmund.core.SigstoreVerifyResult;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import dev.cyberstamp.sigmund.core.TrustRootRef;
import dev.cyberstamp.sigmund.core.VerifyResult;
import dev.sigstore.KeylessSigner;
import dev.sigstore.KeylessSignerException;
import dev.sigstore.KeylessVerificationException;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.bundle.BundleParseException;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * {@link SignatureTool} implementation for Sigstore keyless signing and verification.
 * <p>
 * Wraps sigstore-java's {@link KeylessSigner} and {@link KeylessVerifier}.
 * Unlike OpenPGP tools that shell out to external CLIs, this is a pure-Java
 * implementation — {@link #isAvailable()} always returns {@code true}.
 * <p>
 * The tool is fully configured at construction time. The {@link KeylessSigner}
 * is optional (nullable for verify-only mode). When present, it is reused
 * across multiple {@link #sign(Path, Path, SigningInfo)} calls — sigstore-java internally
 * caches the Fulcio certificate until it has less than 5 minutes of remaining
 * validity.
 * <p>
 * Implements {@link AutoCloseable} to release the {@link KeylessSigner}'s
 * cached ephemeral signing certificate material.
 *
 * @see SigstoreSignatureFormat
 * @see SigstoreToolFactory
 */
public class SigstoreTool implements SignatureTool, AutoCloseable {

    private static final String TOOL_NAME = "sigstore";

    // Sigstore certificate extension OIDs
    private static final String OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
    private static final String OID_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1";
    private static final String FULCIO_OID_PREFIX = "1.3.6.1.4.1.57264.1.";

    /**
     * Fulcio certificate extensions by OID suffix, named as in Fulcio's OID registry. The
     * deprecated GitHub-specific extensions ({@code .2}–{@code .6}) are left out.
     */
    private static final Map<String, String> FULCIO_EXTENSIONS = fulcioExtensions();

    private static Map<String, String> fulcioExtensions() {
        Map<String, String> extensions = new LinkedHashMap<>();
        extensions.put("9", "build-signer-uri");
        extensions.put("10", "build-signer-digest");
        extensions.put("11", "runner-environment");
        extensions.put("12", "source-repository-uri");
        extensions.put("13", "source-repository-digest");
        extensions.put("14", "source-repository-ref");
        extensions.put("15", "source-repository-identifier");
        extensions.put("16", "source-repository-owner-uri");
        extensions.put("17", "source-repository-owner-identifier");
        extensions.put("18", "build-config-uri");
        extensions.put("19", "build-config-digest");
        extensions.put("20", "build-trigger");
        extensions.put("21", "run-invocation-uri");
        extensions.put("22", "source-repository-visibility-at-signing");
        extensions.put("23", "deployment-environment");
        extensions.put("24", "token-subject");
        return Collections.unmodifiableMap(extensions);
    }

    private final SigstoreSignatureFormat format;
    private final KeylessSigner signer;
    private final KeylessVerifier verifier;
    private final String sigstoreSubject;
    private final TrustRootRef trustRoot;
    private final List<IdentityCredential> allowedIdentities;

    /**
     * Creates a new Sigstore tool.
     *
     * @param format the shared signature format instance
     * @param signer the keyless signer, or {@code null} for verify-only mode
     * @param verifier the keyless verifier
     * @param sigstoreSubject the expected OIDC subject for signing info display, or {@code null}
     */
    SigstoreTool(SigstoreSignatureFormat format, KeylessSigner signer, KeylessVerifier verifier,
            String sigstoreSubject) {
        this(format, signer, verifier, sigstoreSubject, TrustRootRef.unknown());
    }

    /**
     * Creates a tool that records which Sigstore trust root it verifies against.
     *
     * @param format the bundle format
     * @param signer the keyless signer, or {@code null} when verify-only
     * @param verifier the keyless verifier, or {@code null} when sign-only
     * @param sigstoreSubject the expected OIDC subject for signing info display, or {@code null}
     * @param trustRoot the trust root the verifier was built with
     */
    SigstoreTool(SigstoreSignatureFormat format, KeylessSigner signer, KeylessVerifier verifier,
            String sigstoreSubject, TrustRootRef trustRoot) {
        this(format, signer, verifier, sigstoreSubject, trustRoot, List.of());
    }

    /**
     * Creates a signing tool that records the identities its signer accepts.
     *
     * @param format the bundle format
     * @param signer the keyless signer
     * @param verifier the keyless verifier, or {@code null} when sign-only
     * @param sigstoreSubject the expected OIDC subject for signing info display, or {@code null}
     * @param trustRoot the trust root the verifier was built with
     * @param allowedIdentities the OIDC identity entries the signer's token must match one of (on
     *        issuer, and on subject when the entry names one), empty when any identity is accepted
     */
    SigstoreTool(SigstoreSignatureFormat format, KeylessSigner signer, KeylessVerifier verifier,
            String sigstoreSubject, TrustRootRef trustRoot, List<IdentityCredential> allowedIdentities) {
        this.allowedIdentities = List.copyOf(allowedIdentities);
        this.trustRoot = trustRoot;
        this.format = format;
        this.signer = signer;
        this.verifier = verifier;
        this.sigstoreSubject = sigstoreSubject;
    }

    /**
     * Returns the OIDC identity entries the signer's token must match one of: on issuer, and on
     * subject when the entry names one.
     *
     * @return the identity entries, empty when any identity is accepted
     */
    List<IdentityCredential> allowedIdentities() {
        return allowedIdentities;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Sigstore verification is local, but which certificates it accepts depends entirely on
     * the TUF-distributed trust root the verifier was built with — the public-good instance,
     * staging, or a private deployment.
     */
    @Override
    public TrustRootRef trustRoot() {
        return trustRoot;
    }

    @Override
    public String name() {
        return TOOL_NAME;
    }

    /**
     * Always returns {@code true} — Sigstore is a pure-Java implementation
     * with no external CLI dependency.
     */
    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public boolean canSign() {
        return signer != null;
    }

    @Override
    public List<SigningInfo> signingInfo() {
        if (!canSign()) {
            return List.of();
        }
        return List.of(new SigningInfo(TOOL_NAME, null, null, sigstoreSubject, Credential.TYPE_SIGSTORE));
    }

    @Override
    public SignatureFormat signatureFormat() {
        return format;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_SIGSTORE);
    }

    @Override
    public boolean canVerify(Claim claim) {
        return claim instanceof SigstoreClaim;
    }

    /**
     * Signs an artifact using the Sigstore keyless flow.
     * <p>
     * Delegates to {@link KeylessSigner#signFile(Path)} which internally
     * handles OIDC authentication, Fulcio certificate issuance, signing,
     * and Rekor transparency log submission. The tool has a single identity, so {@code key}
     * selects nothing.
     *
     * @param artifactFile the file to sign
     * @param outputSig the path to write the Sigstore bundle JSON
     * @param key the key {@link #signingInfo()} reported; ignored
     * @return the signing result with the certificate's public key algorithm
     * @throws ToolExecutionException if signing fails
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig, SigningInfo key) {
        if (signer == null) {
            throw new IllegalStateException("Signing not configured");
        }
        try {
            Bundle bundle = signer.signFile(artifactFile);
            Files.writeString(outputSig, bundle.toJson());

            X509Certificate cert = (X509Certificate) bundle.getCertPath().getCertificates().get(0);
            String algorithm = cert.getPublicKey().getAlgorithm();
            return new SignResult(algorithm);
        } catch (KeylessSignerException e) {
            throw new ToolExecutionException("Sigstore signing failed: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new ToolExecutionException(
                    "Failed to write Sigstore bundle: " + outputSig, e);
        }
    }

    /**
     * Verifies a Sigstore bundle against an artifact.
     * <p>
     * Parses the bundle JSON from the {@link SigstoreClaim}, delegates
     * cryptographic verification to {@link KeylessVerifier#verify(Path, Bundle,
     * dev.sigstore.VerificationOptions)}, and on success populates the result with
     * identity metadata (OIDC issuer, subject, algorithm, Rekor log index) extracted
     * from the Fulcio certificate and Rekor entry in the bundle.
     * <p>
     * The {@code verify} call itself is offline — it validates the bundle against
     * the trusted root fetched at {@link KeylessVerifier} construction time.
     *
     * @param artifactFile the artifact that was signed
     * @param claim the Sigstore claim
     * @return the verification result with OIDC identity and Rekor log index
     * @throws ToolExecutionException for infrastructure failures (network, configuration)
     */
    @Override
    public VerifyResult verify(Path artifactFile, Claim claim) {
        if (verifier == null) {
            throw new IllegalStateException("Verification not configured");
        }
        SigstoreClaim su = (SigstoreClaim) claim;

        Bundle bundle;
        try {
            bundle = Bundle.from(new StringReader(su.jsonBundle()));
        } catch (BundleParseException e) {
            return evidenceMalformed();
        }

        try {
            verifier.verify(artifactFile, bundle, dev.sigstore.VerificationOptions.empty());
        } catch (KeylessVerificationException e) {
            return handleVerificationException(e);
        }

        return buildSuccessResult(bundle);
    }

    /**
     * Extracts proven credentials from a Sigstore verification result.
     * <p>
     * A verified bundle proves one identity: the OIDC issuer that authenticated the signer,
     * with the certificate subject, the subject as {@code email} when it is an address, and
     * every Fulcio certificate extension present. A certificate that names no issuer proves
     * nothing, since an identity is only as good as whoever vouched for it.
     *
     * @param result the verification result
     * @return the proven credentials, or empty if verification did not pass
     */
    @Override
    public List<Credential> extractCredentials(VerifyResult result) {
        if (!result.isVerified()) {
            return List.of();
        }
        IdentityCredential identity = ((SigstoreVerifyResult) result).identity();
        return identity == null ? List.of() : List.of(identity);
    }

    /**
     * Closes the underlying {@link KeylessSigner}, releasing cached ephemeral
     * signing certificate material. No-op for verify-only instances.
     */
    @Override
    public void close() {
        if (signer != null) {
            signer.close();
        }
    }

    /**
     * Maps a verification exception to an outcome, keeping an attack signal distinct from
     * an infrastructure problem.
     *
     * <p>
     * A failure caused by I/O means the trust root could not be reached or read, which says
     * nothing about the artifact: the outcome is indeterminate and transient, so a cached
     * earlier result or a later run can settle it. Anything else means the bundle itself did
     * not verify, which is the attack signal.
     *
     * @param e the exception raised by the Sigstore verifier
     * @return the mapped result
     */
    VerifyResult handleVerificationException(KeylessVerificationException e) {
        if (isInfrastructureFailure(e.getCause())) {
            return SigstoreVerifyResult.indeterminate(IndeterminateReason.TRUST_ROOT_UNAVAILABLE);
        }
        return new SigstoreVerifyResult(ClaimOutcome.FAILED, null, null, null, null, null, -1);
    }

    /**
     * Builds the result for evidence that could not be parsed.
     *
     * <p>
     * A bundle that will not parse has not failed verification — nothing was verified. The
     * reason is permanent: the same bytes will not parse on a later run either.
     *
     * @return an indeterminate result citing malformed evidence
     */
    static VerifyResult evidenceMalformed() {
        return SigstoreVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED);
    }

    private boolean isInfrastructureFailure(Throwable cause) {
        Throwable t = cause;
        while (t != null) {
            if (t instanceof IOException)
                return true;
            t = t.getCause();
        }
        return false;
    }

    private SigstoreVerifyResult buildSuccessResult(Bundle bundle) {
        X509Certificate cert = (X509Certificate) bundle.getCertPath().getCertificates().get(0);

        String subject = extractSubject(cert);
        int subjectType = resolveSubjectType(cert);
        IdentityCredential identity = identityOf(cert);
        String logIndex = extractLogIndex(bundle);
        String algorithm = cert.getPublicKey().getAlgorithm();

        return new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, subject, algorithm,
                identity, logIndex, subjectType);
    }

    /**
     * Extracts the identity a Fulcio certificate proves.
     * <p>
     * The issuer is who vouched; the subject, the subject as an email address when the SAN is
     * an {@code rfc822Name}, and every Fulcio extension present are what it attested.
     *
     * @param cert the Fulcio signing certificate
     * @return the identity, or {@code null} when the certificate names no issuer or attests
     *         nothing
     */
    static IdentityCredential identityOf(X509Certificate cert) {
        String issuer = extractIssuer(cert);
        if (issuer == null) {
            return null;
        }
        Map<String, String> attributes = new LinkedHashMap<>();
        addSubject(attributes, cert);
        for (Map.Entry<String, String> extension : FULCIO_EXTENSIONS.entrySet()) {
            String value = extractExtension(cert, FULCIO_OID_PREFIX + extension.getKey());
            if (value != null && !value.isBlank()) {
                attributes.put(extension.getValue(), value);
            }
        }
        return attributes.isEmpty() ? null : new IdentityCredential(issuer, attributes);
    }

    private static void addSubject(Map<String, String> attributes, X509Certificate cert) {
        String subject = extractSubject(cert);
        if (subject == null) {
            return;
        }
        attributes.put(IdentityCredential.SUBJECT, subject);
        if (resolveSubjectType(cert) == GeneralName.rfc822Name) {
            attributes.put(IdentityCredential.EMAIL, subject);
        }
    }

    /**
     * Extracts the OIDC issuer from Fulcio certificate extensions.
     * <p>
     * Tries V2 OID ({@code 1.3.6.1.4.1.57264.1.8}) first — an ASN1-encoded
     * UTF-8 string. Falls back to V1 OID ({@code 1.3.6.1.4.1.57264.1.1})
     * which contains raw UTF-8 bytes in the octet string.
     */
    private static String extractIssuer(X509Certificate cert) {
        byte[] v2 = cert.getExtensionValue(OID_ISSUER_V2);
        if (v2 != null) {
            return parseAsn1Utf8Extension(v2);
        }
        byte[] v1 = cert.getExtensionValue(OID_ISSUER_V1);
        if (v1 != null) {
            return parseRawUtf8Extension(v1);
        }
        return null;
    }

    /**
     * Extracts a Sigstore certificate extension by OID.
     * <p>
     * Tries ASN.1 UTF-8 string parsing first (handles V2 format), then falls
     * back to raw UTF-8 bytes (handles V1 format). Returns {@code null} if
     * the extension is absent or unparseable.
     *
     * @param cert the certificate to extract from
     * @param oid the extension OID to retrieve
     * @return the UTF-8 string value, or {@code null}
     */
    private static String extractExtension(X509Certificate cert, String oid) {
        byte[] value = cert.getExtensionValue(oid);
        if (value == null)
            return null;
        String asn1 = parseAsn1Utf8Extension(value);
        if (asn1 != null)
            return asn1;
        return parseRawUtf8Extension(value);
    }

    private static String parseAsn1Utf8Extension(byte[] extensionValue) {
        try {
            ASN1OctetString outer = ASN1OctetString.getInstance(extensionValue);
            ASN1UTF8String inner = ASN1UTF8String.getInstance(outer.getOctets());
            return inner.getString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String parseRawUtf8Extension(byte[] extensionValue) {
        try {
            ASN1OctetString outer = ASN1OctetString.getInstance(extensionValue);
            return new String(outer.getOctets(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extracts the signer identity from the certificate's Subject Alternative Name.
     */
    private static String extractSubject(X509Certificate cert) {
        try {
            // Fulcio certs encode the signer identity as a Subject Alternative Name;
            // each SAN is a List of [Integer type, Object value]
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null || sans.isEmpty()) {
                return null;
            }
            // Fulcio issues exactly one SAN — an email (rfc822Name) or OIDC subject URI
            List<?> san = sans.iterator().next();
            return san.size() >= 2 ? san.get(1).toString() : null;
        } catch (CertificateParsingException e) {
            return null;
        }
    }

    /**
     * Resolves the SAN type tag from the certificate.
     *
     * @return the {@link GeneralName} tag value (1 = rfc822Name, 6 = URI), or {@code -1}
     */
    private static int resolveSubjectType(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null || sans.isEmpty()) {
                return -1;
            }
            List<?> san = sans.iterator().next();
            return san.size() >= 2 ? ((Integer) san.get(0)) : -1;
        } catch (CertificateParsingException e) {
            return -1;
        }
    }

    private String extractLogIndex(Bundle bundle) {
        if (bundle.getEntries().isEmpty()) {
            return null;
        }
        return String.valueOf(bundle.getEntries().get(0).getLogIndex());
    }
}
