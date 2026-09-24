package dev.cyberstamp.sigmund.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses {@code sigmund.yaml} configuration files into {@link SigmundConfig}.
 * <p>
 * Maps YAML signer keys to {@link Credential} types:
 * <ul>
 * <li>{@code openpgp4} / {@code pgp4} → {@link FingerprintCredential}("openpgp4", ...)</li>
 * <li>{@code openpgp6} / {@code pgp6} → {@link FingerprintCredential}("openpgp6", ...)</li>
 * <li>{@code email} → {@link EmailCredential}</li>
 * <li>{@code sigstore} → {@link SigstoreCredential}(issuer, subject)</li>
 * </ul>
 */
class SigmundConfigParser {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private SigmundConfigParser() {
    }

    /**
     * Parses a sigmund.yaml file.
     *
     * @param file the path to the YAML file
     * @return the parsed configuration
     * @throws PolicyConfigException if the file cannot be read or is invalid
     */
    static SigmundConfig parse(Path file) {
        try (Reader reader = Files.newBufferedReader(file)) {
            return parse(file.toString(), reader);
        } catch (IOException e) {
            throw new PolicyConfigException("Failed to read config file: " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * Parses a sigmund.yaml from a reader.
     *
     * @param source a human-readable description of the source (e.g., file path)
     * @param reader the YAML source
     * @return the parsed configuration
     * @throws PolicyConfigException if the content is invalid
     */
    static SigmundConfig parse(String source, Reader reader) {
        try {
            JsonNode root = YAML.readTree(reader);
            return parseRoot(root);
        } catch (IOException e) {
            throw new PolicyConfigException(
                    "Failed to parse config " + source + ": " + e.getMessage(), e);
        }
    }

    private static SigmundConfig parseRoot(JsonNode root) {
        int version = root.has("version") ? root.get("version").asInt(1) : 1;
        SignersConfig signers = parseSigners(root.get("signers"));
        SigningConfig signingConfig = parseSigningConfig(root.get("signing"));
        ToolsConfig toolsConfig = parseToolsRegistry(root.get("tools"));
        DiscoveryConfig discoveryConfig = parseDiscoveryConfig(root.get("verification"));

        ArtifactsConfig artifacts = parseArtifactGroups(root.get("artifacts"));
        Map<String, List<String>> rawTrust = parseTrustSection(root.get("trust"));
        Map<String, List<String>> expandedTrust = artifacts.expandTrustMappings(rawTrust);
        List<String> rawUnsigned = parseStringList(root.get("signature-optional"));
        List<String> expandedUnsigned = artifacts.expandPatterns(rawUnsigned);
        ListedEvidencePolicy listedEvidence = parseListedEvidencePolicy(root);
        UnlistedEvidencePolicy unlistedEvidence = parseUnlistedEvidencePolicy(root);
        UntrustedPolicy untrustedPolicy = parseUntrustedPolicy(root);

        Map<String, List<SignerIdentity>> trustMappings = resolveTrustMappings(expandedTrust, signers);
        TrustPolicy trustPolicy = new DefaultTrustPolicy(
                trustMappings, expandedUnsigned, listedEvidence, unlistedEvidence, untrustedPolicy);

        return new SigmundConfig(version, signers, artifacts, trustPolicy,
                signingConfig, toolsConfig, discoveryConfig);
    }

    // --- Signers ---

    private static SignersConfig parseSigners(JsonNode node) {
        if (node == null || node.isNull()) {
            return SignersConfig.EMPTY;
        }
        Map<String, SignerIdentity> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseSigner(entry.getKey(), entry.getValue()));
        }
        return new SignersConfig(result);
    }

    private static SignerIdentity parseSigner(String id, JsonNode node) {
        if (node.isTextual()) {
            return parseMinimalSigner(id, node.asText());
        }
        if (!node.isObject()) {
            throw new PolicyConfigException("Signer '" + id + "' must be a string or object");
        }
        return parseObjectSigner(id, node);
    }

    private static SignerIdentity parseMinimalSigner(String id, String email) {
        if (email.isBlank()) {
            throw new PolicyConfigException("Signer '" + id + "' must not be empty");
        }
        return new SignerIdentity(id, id, List.of(new EmailCredential(email)));
    }

    /**
     * Parses an object-form signer definition.
     * <p>
     * Supports three forms:
     * <ul>
     * <li><b>Single-key signer</b> — credentials (pgp4, pgp6, email, sigstore) at the top level</li>
     * <li><b>Organization with members</b> — a {@code members} array where each element
     * carries its own credentials, all aggregated into one signer identity</li>
     * <li><b>Mixed</b> — top-level credentials and {@code members} combined</li>
     * </ul>
     * At least one credential must be present across the top level and all members.
     *
     * @param id the signer identifier from the YAML key
     * @param node the YAML object node for this signer
     * @return the parsed signer identity with all collected credentials
     * @throws PolicyConfigException if no credentials are found or the members node is invalid
     */
    private static SignerIdentity parseObjectSigner(String id, JsonNode node) {
        String displayName = textField(node, "name");
        List<Credential> credentials = new ArrayList<>();

        addCredentialsFromNode(credentials, node);
        addMemberCredentials(credentials, id, node);

        if (credentials.isEmpty()) {
            throw new PolicyConfigException(
                    "Signer '" + id + "' must have at least one credential (pgp4, pgp6, email, or sigstore)");
        }

        return new SignerIdentity(id, displayName != null ? displayName : id, credentials);
    }

    /**
     * Extracts all credential fields (pgp4, pgp6, email, sigstore) from a single YAML node
     * and appends them to the given list.
     *
     * @param credentials the list to append extracted credentials to
     * @param node the YAML node containing credential fields
     */
    private static void addCredentialsFromNode(List<Credential> credentials, JsonNode node) {
        addFingerprintCredential(credentials, node, "pgp4", Credential.TYPE_OPENPGP_V4);
        addFingerprintCredential(credentials, node, Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V4);
        addFingerprintCredential(credentials, node, "pgp6", Credential.TYPE_OPENPGP_V6);
        addFingerprintCredential(credentials, node, Credential.TYPE_OPENPGP_V6, Credential.TYPE_OPENPGP_V6);
        addEmailCredential(credentials, node);
        addSigstoreCredential(credentials, node);
    }

    /**
     * Parses the {@code members} array of a signer definition, extracting credentials
     * from each member element and appending them to the given list.
     * <p>
     * Nested {@code members} inside a member element are rejected to prevent
     * silent misconfiguration.
     *
     * @param credentials the list to append member credentials to
     * @param signerId the signer identifier, used for error messages
     * @param node the signer YAML node that may contain a {@code members} array
     * @throws PolicyConfigException if {@code members} is present but not an array,
     *         or if a member element contains a nested {@code members} key
     */
    private static void addMemberCredentials(List<Credential> credentials, String signerId, JsonNode node) {
        JsonNode membersNode = node.get("members");
        if (membersNode == null || membersNode.isNull()) {
            return;
        }
        if (!membersNode.isArray()) {
            throw new PolicyConfigException(
                    "Signer '" + signerId + "': 'members' must be an array");
        }
        for (JsonNode member : membersNode) {
            if (!member.isObject()) {
                throw new PolicyConfigException(
                        "Signer '" + signerId + "': each member must be an object");
            }
            if (member.has("members")) {
                throw new PolicyConfigException(
                        "Signer '" + signerId + "': nested 'members' are not allowed");
            }
            addCredentialsFromNode(credentials, member);
        }
    }

    private static void addFingerprintCredential(List<Credential> creds, JsonNode node,
            String yamlKey, String credType) {
        String value = textField(node, yamlKey);
        if (value != null) {
            creds.add(new FingerprintCredential(credType, value));
        }
    }

    private static void addEmailCredential(List<Credential> creds, JsonNode node) {
        String email = textField(node, "email");
        if (email != null) {
            creds.add(new EmailCredential(email));
        }
    }

    private static final List<String> KNOWN_SIGSTORE_FIELDS = List.of(
            "issuer", "subject", "source-repository-uri", "source-repository-owner-uri",
            "build-trigger", "build-config-uri", "runner-environment");

    private static void addSigstoreCredential(List<Credential> creds, JsonNode node) {
        JsonNode sigstoreNode = node.get("sigstore");
        if (sigstoreNode == null || sigstoreNode.isNull()) {
            return;
        }
        if (!sigstoreNode.isObject()) {
            return;
        }
        List<String> unknown = new ArrayList<>();
        sigstoreNode.fieldNames().forEachRemaining(field -> {
            if (!KNOWN_SIGSTORE_FIELDS.contains(field)) {
                unknown.add(field);
            }
        });
        if (!unknown.isEmpty()) {
            throw new PolicyConfigException(
                    "Unknown field(s) in 'sigstore' credential: "
                            + String.join(", ", unknown)
                            + ". Expected: "
                            + String.join(", ", KNOWN_SIGSTORE_FIELDS));
        }
        var builder = new SigstoreCredential.Builder();
        boolean hasField = false;

        String issuer = textField(sigstoreNode, "issuer");
        if (issuer != null) {
            builder.issuer(issuer);
            hasField = true;
        }

        String subject = textField(sigstoreNode, "subject");
        if (subject != null) {
            builder.subject(subject);
            hasField = true;
        }

        String sourceRepositoryUri = textField(sigstoreNode, "source-repository-uri");
        if (sourceRepositoryUri != null) {
            builder.sourceRepositoryUri(sourceRepositoryUri);
            hasField = true;
        }

        String sourceRepositoryOwnerUri = textField(sigstoreNode, "source-repository-owner-uri");
        if (sourceRepositoryOwnerUri != null) {
            builder.sourceRepositoryOwnerUri(sourceRepositoryOwnerUri);
            hasField = true;
        }

        String buildTrigger = textField(sigstoreNode, "build-trigger");
        if (buildTrigger != null) {
            builder.buildTrigger(buildTrigger);
            hasField = true;
        }

        String buildConfigUri = textField(sigstoreNode, "build-config-uri");
        if (buildConfigUri != null) {
            builder.buildConfigUri(buildConfigUri);
            hasField = true;
        }

        String runnerEnvironment = textField(sigstoreNode, "runner-environment");
        if (runnerEnvironment != null) {
            builder.runnerEnvironment(runnerEnvironment);
            hasField = true;
        }

        if (hasField) {
            creds.add(builder.build());
        }
    }

    // --- Signing ---

    private static SigningConfig parseSigningConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return SigningConfig.DEFAULT;
        }
        String signer = textField(node, "signer");
        List<String> toolchain = parseStringList(node.get("toolchain"));
        List<String> credentialTypes = parseStringList(node.get("credential-types"));
        Map<String, List<String>> profiles = parseProfiles(node.get("profiles"));
        return new SigningConfig(signer, toolchain, credentialTypes, profiles);
    }

    private static Map<String, List<String>> parseProfiles(JsonNode node) {
        return parseStringListMap(node);
    }

    // --- Top-level Tools Registry ---

    /**
     * Parses the top-level {@code tools} section into a {@link ToolsConfig} registry.
     * <p>
     * Each tool entry maps a tool name to a {@link ToolConfig} containing optional
     * credentials and tool-specific settings.
     *
     * @param node the {@code tools} YAML node, or {@code null}
     * @return the parsed tool registry, or {@link ToolsConfig#EMPTY} if absent
     */
    private static ToolsConfig parseToolsRegistry(JsonNode node) {
        if (node == null || node.isNull()) {
            return ToolsConfig.EMPTY;
        }
        Map<String, ToolConfig> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseToolConfig(entry.getValue()));
        }
        return new ToolsConfig(result);
    }

    private static ToolConfig parseToolConfig(JsonNode node) {
        List<String> credentials = null;
        JsonNode credsNode = node.get("credentials");
        if (credsNode != null && credsNode.isArray()) {
            credentials = new ArrayList<>();
            for (JsonNode c : credsNode) {
                credentials.add(c.asText());
            }
        }

        Map<String, String> settings = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            if (!"credentials".equals(entry.getKey()) && entry.getValue().isValueNode()) {
                settings.put(entry.getKey(), entry.getValue().asText());
            }
        }
        return new ToolConfig(credentials, settings);
    }

    // --- Trust ---

    private static Map<String, List<String>> parseTrustSection(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseSignerRefs(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    private static List<String> parseSignerRefs(String key, JsonNode node) {
        if (node.isTextual()) {
            return List.of(node.asText());
        }
        if (node.isArray()) {
            List<String> refs = new ArrayList<>();
            for (JsonNode el : node) {
                refs.add(el.asText());
            }
            return Collections.unmodifiableList(refs);
        }
        throw new PolicyConfigException(
                "Trust entry '" + key + "' must be a string or array of strings");
    }

    private static UntrustedPolicy parseUntrustedPolicy(JsonNode root) {
        JsonNode policy = root.get("policy");
        if (policy == null || policy.isNull()) {
            return UntrustedPolicy.FAIL;
        }
        String value = textField(policy, "on-untrusted");
        if (value == null || "fail".equalsIgnoreCase(value)) {
            return UntrustedPolicy.FAIL;
        }
        if ("warn".equalsIgnoreCase(value)) {
            return UntrustedPolicy.WARN;
        }
        throw new PolicyConfigException("Invalid on-untrusted value: '" + value + "' (must be 'fail' or 'warn')");
    }

    private static ListedEvidencePolicy parseListedEvidencePolicy(JsonNode root) {
        JsonNode policy = root.get("policy");
        if (policy == null || policy.isNull()) {
            return ListedEvidencePolicy.ALL;
        }
        String value = textField(policy, "listed-evidence");
        if (value == null || "all".equalsIgnoreCase(value)) {
            return ListedEvidencePolicy.ALL;
        }
        if ("any".equalsIgnoreCase(value)) {
            return ListedEvidencePolicy.ANY;
        }
        throw new PolicyConfigException("Invalid listed-evidence value: '" + value + "' (must be 'all' or 'any')");
    }

    private static UnlistedEvidencePolicy parseUnlistedEvidencePolicy(JsonNode root) {
        JsonNode policy = root.get("policy");
        if (policy == null || policy.isNull()) {
            return UnlistedEvidencePolicy.IGNORE;
        }
        String value = textField(policy, "unlisted-evidence");
        if (value == null || "ignore".equalsIgnoreCase(value)) {
            return UnlistedEvidencePolicy.IGNORE;
        }
        if ("warn".equalsIgnoreCase(value)) {
            return UnlistedEvidencePolicy.WARN;
        }
        if ("require".equalsIgnoreCase(value)) {
            return UnlistedEvidencePolicy.REQUIRE;
        }
        throw new PolicyConfigException(
                "Invalid unlisted-evidence value: '" + value + "' (must be 'ignore', 'warn', or 'require')");
    }

    // --- Trust Mapping Resolution ---

    /**
     * Resolves signer references in trust mappings to actual {@link SignerIdentity}
     * instances using the given {@link SignersConfig} registry.
     *
     * @param rawTrust expanded trust mappings with signer name references
     * @param signers the signer registry for resolving references
     * @return resolved trust mappings with signer identities
     * @throws PolicyConfigException if a referenced signer is not defined
     */
    private static Map<String, List<SignerIdentity>> resolveTrustMappings(
            Map<String, List<String>> rawTrust,
            SignersConfig signers) {
        var result = new LinkedHashMap<String, List<SignerIdentity>>(rawTrust.size());
        for (var entry : rawTrust.entrySet()) {
            List<String> signerRefs = entry.getValue();
            List<SignerIdentity> resolved = new ArrayList<>(signerRefs.size());
            for (String ref : signerRefs) {
                try {
                    resolved.add(signers.resolve(ref));
                } catch (PolicyConfigException e) {
                    throw new PolicyConfigException(
                            "Trust entry '" + entry.getKey() + "' references undefined signer '" + ref + "'");
                }
            }
            result.put(entry.getKey(), List.copyOf(resolved));
        }
        return result;
    }

    // --- Artifact Groups ---

    private static ArtifactsConfig parseArtifactGroups(JsonNode node) {
        Map<String, List<String>> groups = parseStringListMap(node);
        return new ArtifactsConfig(groups);
    }

    private static Map<String, List<String>> parseStringListMap(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseStringList(entry.getValue()));
        }
        return result;
    }

    // --- Discovery ---

    /**
     * Parses the {@code discovery} section into a {@link DiscoveryConfig}.
     * <p>
     * Contains operational concerns: key fetching behavior, keyserver URLs,
     * and the verification toolchain priority.
     *
     * @param node the {@code discovery} YAML node, or {@code null}
     * @return the parsed discovery configuration
     */
    private static DiscoveryConfig parseDiscoveryConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return DiscoveryConfig.DEFAULT;
        }
        boolean resolveSigners = boolOrDefault(node, "resolve-signers", true);
        boolean importToKeyring = boolOrDefault(node, "import-to-keyring", false);
        List<String> keyservers = parseStringList(node.get("keyservers"));
        JsonNode tcNode = node.get("toolchain");
        List<String> toolchain = (tcNode != null && !tcNode.isNull()) ? parseStringList(tcNode) : null;
        return new DiscoveryConfig(resolveSigners, importToKeyring, keyservers, toolchain);
    }

    // --- Utilities ---

    private static List<String> parseStringList(JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (node.isTextual()) {
            String text = node.asText();
            return text.isEmpty() ? List.of() : List.of(text);
        }
        if (!node.isArray()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (JsonNode el : node) {
            if (!el.isNull()) {
                result.add(el.asText());
            }
        }
        return Collections.unmodifiableList(result);
    }

    private static String textField(JsonNode node, String field) {
        JsonNode child = node.get(field);
        return child != null && !child.isNull() && child.isValueNode() ? child.asText() : null;
    }

    private static boolean boolOrDefault(JsonNode node, String field, boolean defaultValue) {
        JsonNode child = node.get(field);
        return child != null && !child.isNull() ? child.asBoolean() : defaultValue;
    }

}
