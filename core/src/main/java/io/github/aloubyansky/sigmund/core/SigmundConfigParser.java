package io.github.aloubyansky.sigmund.core;

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
 * <li>{@code oidc} → {@link OidcCredential}(issuer, subject)</li>
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
            return parse(reader);
        } catch (IOException e) {
            throw new PolicyConfigException("Failed to read config file: " + file, e);
        }
    }

    /**
     * Parses a sigmund.yaml from a reader.
     *
     * @param reader the YAML source
     * @return the parsed configuration
     * @throws PolicyConfigException if the content is invalid
     */
    static SigmundConfig parse(Reader reader) {
        try {
            JsonNode root = YAML.readTree(reader);
            return parseRoot(root);
        } catch (IOException e) {
            throw new PolicyConfigException("Failed to parse config", e);
        }
    }

    private static SigmundConfig parseRoot(JsonNode root) {
        int version = root.has("version") ? root.get("version").asInt(1) : 1;
        Map<String, SignerIdentity> signers = parseSigners(root.get("signers"));
        SigningConfig signingConfig = parseSigningConfig(root.get("signing"));
        DiscoveryConfig discoveryConfig = parseDiscoveryConfig(root.get("discovery"));

        Map<String, List<String>> rawTrust = parseTrustSection(root.get("trust"));
        List<String> unsigned = parseStringList(root.get("unsigned"));
        boolean requireAll = boolField(root, "policy", "require-all-evidence-match", true);
        UntrustedPolicy untrustedPolicy = parseUntrustedPolicy(root);

        Map<String, List<SignerIdentity>> trustMappings = DefaultTrustPolicy.resolveTrustMappings(rawTrust, signers);
        TrustPolicy trustPolicy = new DefaultTrustPolicy(
                trustMappings, unsigned, requireAll, untrustedPolicy);

        return new SigmundConfig(version, signers, trustPolicy, signingConfig, discoveryConfig);
    }

    // --- Signers ---

    private static Map<String, SignerIdentity> parseSigners(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, SignerIdentity> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseSigner(entry.getKey(), entry.getValue()));
        }
        return result;
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
        return new SignerIdentity(id, null, List.of(new EmailCredential(email)));
    }

    private static SignerIdentity parseObjectSigner(String id, JsonNode node) {
        String displayName = textField(node, "name");
        List<Credential> credentials = new ArrayList<>();

        addFingerprintCredential(credentials, node, Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V4);
        addFingerprintCredential(credentials, node, "pgp4", Credential.TYPE_OPENPGP_V4);
        addFingerprintCredential(credentials, node, Credential.TYPE_OPENPGP_V6, Credential.TYPE_OPENPGP_V6);
        addFingerprintCredential(credentials, node, "pgp6", Credential.TYPE_OPENPGP_V6);
        addEmailCredential(credentials, node);
        addOidcCredential(credentials, node);

        return new SignerIdentity(id, displayName, credentials);
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

    private static void addOidcCredential(List<Credential> creds, JsonNode node) {
        JsonNode oidcNode = node.get("oidc");
        if (oidcNode == null || oidcNode.isNull()) {
            return;
        }
        if (oidcNode.isObject()) {
            String issuer = textField(oidcNode, "issuer");
            String subject = textField(oidcNode, "subject");
            if (issuer != null && subject != null) {
                creds.add(new OidcCredential(issuer, subject));
            }
        }
    }

    // --- Signing ---

    private static SigningConfig parseSigningConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return SigningConfig.DEFAULT;
        }
        String signer = textField(node, "signer");
        Map<String, ToolConfig> tools = parseToolConfigs(node.get("tools"));
        Map<String, List<String>> profiles = parseProfiles(node.get("profiles"));
        String defaultProfile = textField(node, "default-profile");
        return new SigningConfig(signer, tools, profiles, defaultProfile);
    }

    private static Map<String, ToolConfig> parseToolConfigs(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, ToolConfig> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            result.put(entry.getKey(), parseToolConfig(entry.getValue()));
        }
        return result;
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

    private static Map<String, List<String>> parseProfiles(JsonNode node) {
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

    // --- Discovery ---

    private static DiscoveryConfig parseDiscoveryConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return DiscoveryConfig.DEFAULT;
        }
        boolean fetchSignerInfo = boolOrDefault(node, "fetch-signer-info", true);
        boolean importToKeyring = boolOrDefault(node, "import-to-keyring", false);
        List<String> keyservers = parseStringList(node.get("keyservers"));
        Map<String, Map<String, String>> tools = parseDiscoveryTools(node.get("tools"));
        return new DiscoveryConfig(fetchSignerInfo, importToKeyring, keyservers, tools);
    }

    private static Map<String, Map<String, String>> parseDiscoveryTools(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, Map<String, String>> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            Map<String, String> settings = new LinkedHashMap<>();
            Iterator<Map.Entry<String, JsonNode>> toolFields = entry.getValue().fields();
            while (toolFields.hasNext()) {
                Map.Entry<String, JsonNode> tf = toolFields.next();
                settings.put(tf.getKey(), tf.getValue().asText());
            }
            result.put(entry.getKey(), Map.copyOf(settings));
        }
        return result;
    }

    // --- Utilities ---

    private static List<String> parseStringList(JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (!node.isArray()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (JsonNode el : node) {
            result.add(el.asText());
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

    private static boolean boolField(JsonNode root, String section, String field, boolean defaultValue) {
        JsonNode sectionNode = root.get(section);
        if (sectionNode == null || sectionNode.isNull()) {
            return defaultValue;
        }
        return boolOrDefault(sectionNode, field, defaultValue);
    }
}
