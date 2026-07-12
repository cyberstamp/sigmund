package io.github.aloubyansky.sigmund.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Custom Jackson deserializer for {@link TrustConfig} that handles the three
 * signer definition forms and normalizes trust values to lists.
 */
class TrustConfigDeserializer extends StdDeserializer<TrustConfig> {

    TrustConfigDeserializer() {
        super(TrustConfig.class);
    }

    @Override
    public TrustConfig deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode root = p.readValueAsTree();

        var settings = parseSettings(root.get("settings"));
        var signers = parseSigners(root.get("signers"));
        var artifacts = parseArtifacts(root.get("artifacts"));
        var trust = parseTrust(root.get("trust"));
        var unsigned = parseUnsigned(root.get("unsigned"));

        return new TrustConfig(settings, signers, artifacts, trust, unsigned);
    }

    private TrustConfig.Settings parseSettings(JsonNode node) {
        if (node == null || node.isNull()) {
            return TrustConfig.Settings.defaults();
        }
        var keyservers = parseStringList(node.get("keyservers"));
        var onUntrusted = textOrDefault(node, "on-untrusted", "fail");
        var verifyAll = boolOrDefault(node, "verify-all-signatures", true);
        var fetchInfo = boolOrDefault(node, "fetch-signer-info", true);
        return new TrustConfig.Settings(keyservers, onUntrusted, verifyAll, fetchInfo);
    }

    private Map<String, TrustConfig.Signer> parseSigners(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, TrustConfig.Signer> result = new LinkedHashMap<>();
        var fields = node.fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            result.put(entry.getKey(), parseSigner(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    /**
     * Parses a single signer definition from one of three forms:
     * <ul>
     * <li>String → minimal (email only)</li>
     * <li>Object with "members" → full form</li>
     * <li>Object without "members" → short form (single credential)</li>
     * </ul>
     */
    private TrustConfig.Signer parseSigner(String id, JsonNode node) {
        if (node.isTextual()) {
            return parseMinimalSigner(id, node);
        }
        if (!node.isObject()) {
            throw new IllegalArgumentException(
                    "Signer '" + id + "' must be a string or object");
        }
        ObjectNode obj = (ObjectNode) node;
        if (obj.has("members")) {
            return parseFullSigner(id, obj);
        }
        return parseShortSigner(id, obj);
    }

    private TrustConfig.Signer parseMinimalSigner(String id, JsonNode node) {
        String email = node.asText();
        if (email.isBlank()) {
            throw new IllegalArgumentException(
                    "Signer '" + id + "' must not be empty");
        }
        return new TrustConfig.Signer(null, List.of(new TrustConfig.Member(null, null, email)));
    }

    private TrustConfig.Signer parseFullSigner(String id, ObjectNode obj) {
        String name = obj.has("name") ? obj.get("name").asText() : null;
        JsonNode membersNode = obj.get("members");
        if (!membersNode.isArray() || membersNode.isEmpty()) {
            throw new IllegalArgumentException(
                    "Signer '" + id + "' members must be a non-empty array");
        }
        List<TrustConfig.Member> members = new ArrayList<>();
        for (JsonNode memberNode : membersNode) {
            members.add(parseMember(id, memberNode));
        }
        return new TrustConfig.Signer(name, Collections.unmodifiableList(members));
    }

    private TrustConfig.Signer parseShortSigner(String id, ObjectNode obj) {
        var member = parseMember(id, obj);
        return new TrustConfig.Signer(null, List.of(member));
    }

    private TrustConfig.Member parseMember(String signerId, JsonNode node) {
        if (!node.isObject()) {
            throw new IllegalArgumentException(
                    "Member entry in signer '" + signerId + "' must be an object");
        }
        String pgp4 = textOrDefault(node, "pgp4", null);
        String pgp6 = textOrDefault(node, "pgp6", null);
        String email = textOrDefault(node, "email", null);
        if (pgp4 == null && pgp6 == null && email == null) {
            throw new IllegalArgumentException(
                    "Member entry in signer '" + signerId + "' must have at least one of: pgp4, pgp6, email");
        }
        if (email != null && email.isBlank()) {
            throw new IllegalArgumentException(
                    "Member entry in signer '" + signerId + "' has an empty email");
        }
        return new TrustConfig.Member(pgp4, pgp6, email);
    }

    private Map<String, List<String>> parseArtifacts(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        var fields = node.fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            result.put(entry.getKey(), parseStringList(entry.getValue()));
        }
        return result;
    }

    /**
     * Parses the trust section, normalizing single-string values to single-element lists.
     */
    private Map<String, List<String>> parseTrust(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        var fields = node.fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            result.put(entry.getKey(), parseSignerRefs(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    /**
     * Parses a signer reference value, which can be a single string or an array of strings.
     */
    private List<String> parseSignerRefs(String artifactKey, JsonNode node) {
        if (node.isTextual()) {
            return List.of(node.asText());
        }
        if (node.isArray()) {
            List<String> refs = new ArrayList<>();
            for (JsonNode element : node) {
                if (!element.isTextual()) {
                    throw new IllegalArgumentException(
                            "Trust entry '" + artifactKey + "' array elements must be strings");
                }
                refs.add(element.asText());
            }
            return Collections.unmodifiableList(refs);
        }
        throw new IllegalArgumentException(
                "Trust entry '" + artifactKey + "' must be a string or array of strings");
    }

    private List<String> parseUnsigned(JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        return parseStringList(node);
    }

    private List<String> parseStringList(JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (!node.isArray()) {
            throw new IllegalArgumentException("Expected an array but got " + node.getNodeType());
        }
        List<String> result = new ArrayList<>();
        for (JsonNode element : node) {
            result.add(element.asText());
        }
        return Collections.unmodifiableList(result);
    }

    private String textOrDefault(JsonNode parent, String field, String defaultValue) {
        JsonNode node = parent.get(field);
        return node != null && !node.isNull() ? node.asText() : defaultValue;
    }

    private boolean boolOrDefault(JsonNode parent, String field, boolean defaultValue) {
        JsonNode node = parent.get(field);
        return node != null && !node.isNull() ? node.asBoolean() : defaultValue;
    }
}
