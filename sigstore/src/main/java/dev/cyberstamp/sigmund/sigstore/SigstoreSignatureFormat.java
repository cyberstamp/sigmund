package dev.cyberstamp.sigmund.sigstore;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cyberstamp.sigmund.core.Claim;
import dev.cyberstamp.sigmund.core.Evidence;
import dev.cyberstamp.sigmund.core.SignatureFormat;
import dev.cyberstamp.sigmund.core.SigstoreClaim;
import java.time.Instant;
import java.util.List;

/**
 * Signature format for Sigstore bundles ({@code .sigstore.json}).
 * <p>
 * Each bundle is a standalone JSON file containing the Fulcio certificate,
 * message signature, and Rekor transparency log entry. Unlike OpenPGP where
 * one {@code .asc} file may contain multiple armored blocks, a Sigstore
 * bundle is always a single verifiable claim.
 *
 * @see SignatureFormat
 * @see SigstoreClaim
 */
public class SigstoreSignatureFormat implements SignatureFormat {

    /** Format name, as used in toolchain and credential-type configuration. */
    public static final String FORMAT_SIGSTORE = "sigstore";

    /** Media type every Sigstore bundle declares, whatever its version. */
    private static final String SIGSTORE_MEDIA_TYPE_PREFIX = "application/vnd.dev.sigstore.bundle";

    /** Bytes of a bundle read when sniffing content, enough to reach the media type. */
    private static final int SNIFF_LENGTH = 1024;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * {@inheritDoc}
     *
     * @return {@code "sigstore"}
     */
    @Override
    public String name() {
        return FORMAT_SIGSTORE;
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code ".sigstore.json"}
     */
    @Override
    public String fileExtension() {
        return ".sigstore.json";
    }

    /**
     * Detects Sigstore bundles by looking for the Sigstore media type in the file's opening
     * bytes.
     *
     * <p>
     * Content that does not begin with <code>{</code> is rejected immediately. Otherwise the
     * first {@value #SNIFF_LENGTH} characters must carry a {@code "mediaType"} field
     * whose value starts with {@code "application/vnd.dev.sigstore.bundle"}, which every
     * bundle version declares.
     *
     * @param evidence the evidence to check
     * @return {@code true} when it appears to be a Sigstore bundle
     */
    @Override
    public boolean canHandleByContent(Evidence evidence) {
        String content = evidence.text();
        String head = content.length() > SNIFF_LENGTH
                ? content.substring(0, SNIFF_LENGTH)
                : content;
        head = head.trim();
        if (!head.startsWith("{")) {
            return false;
        }
        return head.contains("\"mediaType\"") && head.contains(SIGSTORE_MEDIA_TYPE_PREFIX);
    }

    /**
     * Parses a Sigstore bundle into a single {@link SigstoreClaim}.
     *
     * <p>
     * A bundle is always one claim: unlike an OpenPGP {@code .asc}, which may carry a classic
     * and a post-quantum block, a bundle holds one certificate and one signature.
     *
     * <p>
     * The bundle text is carried verbatim for the tool to verify; the only field read here is
     * the log entry's integrated time, which becomes the claim's time. Parsing never decides
     * an outcome — a bundle that will not verify, or will not even parse, still yields a claim
     * and the tool reports why.
     *
     * @param evidence the Sigstore bundle
     * @return a single-element list containing the claim
     */
    @Override
    public List<Claim> parse(Evidence evidence) {
        String json = evidence.text();
        return List.of(new SigstoreClaim(json, extractIntegratedTime(json)));
    }

    /**
     * Reads the transparency log entry's integrated time from a bundle.
     *
     * <p>
     * This is the instant Rekor recorded and countersigned, which is what makes a Sigstore
     * claim's time independent of the signer (see
     * {@link dev.cyberstamp.sigmund.core.ClaimTimeSource#TRANSPARENCY_LOG}). The field is read
     * straight from the JSON rather than through a full bundle parse, so that a bundle which
     * will not verify still reports when it was logged.
     *
     * <p>
     * Protobuf's JSON mapping renders an {@code int64} as a string, so the value is accepted
     * in either form.
     *
     * <p>
     * The bundle is therefore read twice: once here, and again by {@code SigstoreTool} when it
     * verifies. That is deliberate. Moving this into the tool would not remove a parse —
     * sigstore-java parses the bundle from text either way — and it would lose the claim time
     * for a bundle that does not verify, which is exactly when knowing when it was logged
     * helps. This read is a small tree walk; the tool's is the full bundle.
     *
     * @param json the bundle's JSON text
     * @return the integrated time, or {@code null} when the bundle carries none
     */
    private static Instant extractIntegratedTime(String json) {
        try {
            JsonNode entries = MAPPER.readTree(json)
                    .path("verificationMaterial")
                    .path("tlogEntries");
            if (!entries.isArray() || entries.isEmpty()) {
                return null;
            }
            JsonNode integratedTime = entries.get(0).path("integratedTime");
            if (integratedTime.isMissingNode() || integratedTime.isNull()) {
                return null;
            }
            return Instant.ofEpochSecond(integratedTime.asLong());
        } catch (JsonProcessingException | RuntimeException e) {
            return null;
        }
    }
}
