package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

/**
 * Parses {@code sigmund.yaml} configuration files into {@link SigmundConfig}.
 * <p>
 * Maps YAML signer keys to {@link Credential}s:
 * <ul>
 * <li>{@code pgp4}, {@code pgp6} → one {@link KeyCredential} per fingerprint, a single one or
 * a list of them, full fingerprints only</li>
 * <li>{@code email} → an {@link IdentityCredential} asserting {@code email}, vouched for by
 * one of the top-level {@code issuers}</li>
 * <li>{@code identities} → one {@link IdentityCredential} per entry: an optional
 * {@code issuer}, otherwise the top-level {@code issuers}, and the attributes it must
 * have attested</li>
 * </ul>
 * Identity entries and issuers are checked by {@link IdentityEntryValidator} when the policy is
 * compiled on the verification path, not at parse time, so the signing path never fails on a
 * verification-only semantic error. The one exception is the signer {@code signing.signer}
 * asserts: its own entries are checked at load, since signing relies on them, without compiling
 * the policy. The parser only normalizes issuer names it recognizes and keeps any other as
 * written.
 */
class SigmundConfigParser {

    private static final ObjectMapper YAML = new YAMLMapper();

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
        return parseRoot(readTree(source, reader));
    }

    /**
     * Reads a {@code sigmund.yaml} into a tree, as YAML 1.2 with the JSON schema: only
     * {@code true}, {@code false}, {@code null} and JSON numbers are typed, so {@code yes},
     * {@code ~}, {@code 0x12345678} and {@code 0123} stay as written instead of becoming a
     * boolean, a null or a number the author did not mean.
     *
     * @param source a human-readable description of the source, for the error message
     * @param reader the YAML source
     * @return the document's tree, a missing node when the document is empty
     * @throws PolicyConfigException if the content is not well-formed YAML
     */
    static JsonNode readTree(String source, Reader reader) {
        try {
            return YAML.readTree(reader);
        } catch (JacksonException e) {
            throw new PolicyConfigException(
                    "Failed to parse config " + source + ": " + e.getMessage(), e);
        }
    }

    private static SigmundConfig parseRoot(JsonNode root) {
        if (root.has("trust")) {
            throw new PolicyConfigException(
                    "The 'trust' key is no longer supported; use 'rules' instead");
        }
        if (root.has("signature-optional")) {
            throw new PolicyConfigException(
                    "The 'signature-optional' key is no longer supported; use 'rules' with "
                            + "enforcement overrides (e.g., 'on-no-claim: ignore') instead");
        }
        if (root.has("policy")) {
            throw new PolicyConfigException(
                    "The 'policy' key is no longer supported; use 'rules' instead");
        }
        if (root.has("version")) {
            throw new PolicyConfigException(
                    "The 'version' key is no longer supported; remove it");
        }
        if (root.has("artifacts")) {
            throw new PolicyConfigException(
                    "The 'artifacts' key is no longer supported; use 'artifact-sets' instead");
        }

        rejectUnknownTopLevelKeys(root);

        SignersConfig signers = parseSigners(root.get("signers"));
        List<String> issuers = parseIssuers(root.get("issuers"));
        SigningConfig signingConfig = parseSigningConfig(root.get("signing"));
        requireDefinedSigner(signingConfig, signers);
        validateAssertedSigner(signingConfig, signers, issuers);
        ToolsConfig toolsConfig = parseToolsRegistry(root.get("tools"));
        VerificationConfig verificationConfig = parseVerificationConfig(root.get("verification"));

        ArtifactSetsConfig artifactSets = parseArtifactGroups(root.get("artifact-sets"));
        TrustPolicySpec trustPolicySpec = parseTrustPolicySpec(root, artifactSets, issuers);

        return new SigmundConfig(signers, artifactSets, trustPolicySpec,
                signingConfig, toolsConfig, verificationConfig);
    }

    private static void requireDefinedSigner(SigningConfig signingConfig, SignersConfig signers) {
        String name = signingConfig.signer();
        if (name == null || signers.names().contains(name)) {
            return;
        }
        String suggestion = NearestName.among(name, signers.names());
        throw new PolicyConfigException("signing.signer names '" + name
                + "', which is not defined under signers"
                + (suggestion == null ? "" : " — did you mean '" + suggestion + "'?"));
    }

    private static void validateAssertedSigner(SigningConfig signingConfig, SignersConfig signers,
            List<String> issuers) {
        String name = signingConfig.signer();
        if (name != null) {
            IdentityEntryValidator.validateAssertedSigner(name, signers.get(name), issuers);
        }
    }

    private static final List<String> TOP_LEVEL_KEYS = List.of("issuers", "signers",
            "signing", "tools", "verification", "artifact-sets", "rules", "defaults");

    /**
     * Rejects top-level keys the schema does not define.
     * <p>
     * An ignored key would silently drop what the author wrote, and for the policy sections that
     * fails open: a misspelled {@code rules} would leave a file with no policy, which observes
     * rather than enforces.
     */
    private static void rejectUnknownTopLevelKeys(JsonNode root) {
        for (Map.Entry<String, JsonNode> field : root.properties()) {
            String key = field.getKey();
            if (!TOP_LEVEL_KEYS.contains(key)) {
                String suggestion = NearestName.among(key, TOP_LEVEL_KEYS);
                throw new PolicyConfigException("Unknown top-level key '" + key + "'"
                        + (suggestion == null
                                ? "; expected one of " + String.join(", ", TOP_LEVEL_KEYS)
                                : " — did you mean '" + suggestion + "'?"));
            }
        }
    }

    // --- Issuers ---

    private static List<String> parseIssuers(JsonNode node) {
        List<String> issuers = new ArrayList<>();
        for (String name : stringList(node, "issuers")) {
            String canonical = IssuerKind.canonicalName(name);
            if (!issuers.contains(canonical)) {
                issuers.add(canonical);
            }
        }
        return List.copyOf(issuers);
    }

    // --- Signers ---

    private static SignersConfig parseSigners(JsonNode node) {
        if (node == null || node.isNull()) {
            return SignersConfig.EMPTY;
        }
        Map<String, SignerIdentity> result = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            result.put(entry.getKey(), parseSigner(entry.getKey(), entry.getValue()));
        }
        return new SignersConfig(result);
    }

    private static SignerIdentity parseSigner(String id, JsonNode node) {
        if (node.isString()) {
            return parseMinimalSigner(id, node.asString());
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
        return new SignerIdentity(id, List.of(identity(id, null, Map.of(IdentityCredential.EMAIL, email))));
    }

    private static final List<String> SIGNING_CREDENTIAL_TYPES = List.of(
            Credential.TYPE_PGP4, Credential.TYPE_PGP6, Credential.TYPE_SIGSTORE);
    private static final String EXTRA_CLAIMS = "extra-claims";
    private static final String MEMBERS = "members";
    private static final String IDENTITIES = "identities";
    private static final String ISSUER = "issuer";
    private static final List<String> CREDENTIAL_KEYS = List.of(
            "pgp4", "pgp6", IdentityCredential.EMAIL, IDENTITIES);

    /**
     * Parses an object-form signer definition.
     * <p>
     * Supports three forms:
     * <ul>
     * <li><b>Single signer</b> — credentials ({@code pgp4}, {@code pgp6}, {@code email},
     * {@code identities}) at the top level</li>
     * <li><b>Organization with members</b> — a {@code members} array where each element
     * carries its own credentials, all aggregated into one signer identity</li>
     * <li><b>Mixed</b> — top-level credentials and {@code members} combined</li>
     * </ul>
     * At least one credential must be present across the top level and all members. Unknown
     * keys are errors: an ignored key would silently drop a credential the author wrote.
     *
     * @param id the signer identifier from the YAML key
     * @param node the YAML object node for this signer
     * @return the parsed signer identity with all collected credentials
     * @throws PolicyConfigException if no credentials are found, a key is unknown, or the
     *         members node is invalid
     */
    private static SignerIdentity parseObjectSigner(String id, JsonNode node) {
        List<String> known = new ArrayList<>(CREDENTIAL_KEYS);
        known.add(MEMBERS);
        rejectUnknownKeys(id, node, known);
        List<Credential> credentials = new ArrayList<>();

        addCredentialsFromNode(credentials, id, node);
        addMemberCredentials(credentials, id, node);

        if (credentials.isEmpty()) {
            throw new PolicyConfigException("Signer '" + id
                    + "' must have at least one credential (pgp4, pgp6, email or identities)");
        }

        return new SignerIdentity(id, credentials);
    }

    /**
     * Extracts all credentials ({@code pgp4}, {@code pgp6}, {@code email}, {@code identities})
     * from a single YAML node and appends them to the given list.
     *
     * @param credentials the list to append extracted credentials to
     * @param signerId the signer identifier, used for error messages
     * @param node the YAML node containing credential fields
     */
    private static void addCredentialsFromNode(List<Credential> credentials, String signerId,
            JsonNode node) {
        addKeyCredentials(credentials, signerId, node, "pgp4", Credential.TYPE_PGP4);
        addKeyCredentials(credentials, signerId, node, "pgp6", Credential.TYPE_PGP6);
        addEmailCredential(credentials, signerId, node);
        addIdentities(credentials, signerId, node);
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
     *         or if a member element contains an unknown key or nested {@code members}
     */
    private static void addMemberCredentials(List<Credential> credentials, String signerId, JsonNode node) {
        JsonNode membersNode = node.get(MEMBERS);
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
            if (member.has(MEMBERS)) {
                throw new PolicyConfigException(
                        "Signer '" + signerId + "': nested 'members' are not allowed");
            }
            rejectUnknownKeys(signerId, member, CREDENTIAL_KEYS);
            addCredentialsFromNode(credentials, signerId, member);
        }
    }

    private static void addKeyCredentials(List<Credential> creds, String signerId,
            JsonNode node, String yamlKey, String keyType) {
        JsonNode value = node.get(yamlKey);
        if (value == null || value.isNull()) {
            return;
        }
        for (JsonNode fingerprint : fingerprintNodes(value, signerId, yamlKey)) {
            creds.add(keyCredential(fingerprint.asString(), signerId, yamlKey, keyType));
        }
    }

    /**
     * Returns the fingerprints a {@code pgp4} or {@code pgp6} value lists: the value itself when
     * it is a single fingerprint, otherwise the elements of its list. Any other shape is an error
     * rather than an empty result, which would silently drop the keys the author wrote.
     */
    private static List<JsonNode> fingerprintNodes(JsonNode value, String signerId, String yamlKey) {
        List<JsonNode> fingerprints = value.isArray() ? new ArrayList<>() : List.of(value);
        if (value.isArray()) {
            value.forEach(fingerprints::add);
        }
        for (JsonNode fingerprint : fingerprints) {
            if (!fingerprint.isString()) {
                throw new PolicyConfigException("Signer '" + signerId + "': '" + yamlKey
                        + "' must be a fingerprint or a list of fingerprints, not " + describe(value));
            }
        }
        return fingerprints;
    }

    private static KeyCredential keyCredential(String fingerprint, String signerId, String yamlKey,
            String keyType) {
        try {
            return new KeyCredential(keyType, fingerprint);
        } catch (IllegalArgumentException e) {
            throw new PolicyConfigException(
                    "Signer '" + signerId + "': '" + yamlKey + "' " + e.getMessage(), e);
        }
    }

    /**
     * Adds the {@code email} shorthand: an address vouched for by one of the listed issuers.
     */
    private static void addEmailCredential(List<Credential> creds, String signerId,
            JsonNode node) {
        JsonNode email = node.get(IdentityCredential.EMAIL);
        if (email == null || email.isNull()) {
            return;
        }
        if (!email.isString()) {
            throw new PolicyConfigException("Signer '" + signerId
                    + "': 'email' must be an address; to name its issuer, use 'identities'");
        }
        creds.add(identity(signerId, null, Map.of(IdentityCredential.EMAIL, email.asString())));
    }

    /**
     * Adds the {@code identities} list: each entry an optional {@code issuer} plus the
     * attributes it must have attested.
     */
    private static void addIdentities(List<Credential> creds, String signerId, JsonNode node) {
        JsonNode identities = node.get(IDENTITIES);
        if (identities == null || identities.isNull()) {
            return;
        }
        if (!identities.isArray()) {
            throw new PolicyConfigException("Signer '" + signerId + "': 'identities' must be a list");
        }
        for (JsonNode entry : identities) {
            if (!entry.isObject()) {
                throw new PolicyConfigException("Signer '" + signerId
                        + "': each identity must be a map of an optional 'issuer' and attributes");
            }
            creds.add(identity(signerId, inlineIssuer(entry), attributesOf(entry)));
        }
    }

    private static Map<String, String> attributesOf(JsonNode entry) {
        Map<String, String> attributes = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> field : entry.properties()) {
            if (!ISSUER.equals(field.getKey())) {
                attributes.put(field.getKey(), field.getValue().asString());
            }
        }
        return attributes;
    }

    private static String inlineIssuer(JsonNode entry) {
        String issuer = textField(entry, ISSUER);
        return issuer == null ? null : IssuerKind.canonicalName(issuer);
    }

    private static IdentityCredential identity(String signerId, String issuer,
            Map<String, String> attributes) {
        try {
            return new IdentityCredential(issuer, attributes);
        } catch (IllegalArgumentException e) {
            throw new PolicyConfigException("Signer '" + signerId
                    + "': an identity needs at least one attribute besides its issuer, "
                    + "each with a value", e);
        }
    }

    private static void rejectUnknownKeys(String signerId, JsonNode node, List<String> known) {
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            if (!known.contains(field.getKey())) {
                throw new PolicyConfigException("Signer '" + signerId + "': unknown key '"
                        + field.getKey() + "'; expected " + String.join(", ", known));
            }
        }
    }

    // --- Signing ---

    private static final List<String> SIGNING_KEYS = List.of("signer", "toolchain",
            "credential-types", "profiles");

    private static SigningConfig parseSigningConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return SigningConfig.DEFAULT;
        }
        checkSection(node, "signing", SIGNING_KEYS);
        String signer = signerField(node.get("signer"));
        List<String> toolchain = stringList(node.get("toolchain"), "signing.toolchain");
        List<String> credentialTypes = credentialTypes(
                stringList(node.get("credential-types"), "signing.credential-types"));
        Map<String, List<String>> profiles = parseProfiles(node.get("profiles"));
        return new SigningConfig(signer, toolchain, credentialTypes, profiles);
    }

    private static String signerField(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.isString()) {
            throw new PolicyConfigException("signing.signer must be a signer id, not " + describe(node));
        }
        return node.asString();
    }

    private static Map<String, List<String>> parseProfiles(JsonNode node) {
        if (node != null && !node.isNull() && !node.isObject()) {
            throw new PolicyConfigException(
                    "signing.profiles must map profile names to credential types, not " + describe(node));
        }
        Map<String, List<String>> profiles = new LinkedHashMap<>();
        stringListMap(node, "signing.profiles")
                .forEach((name, types) -> profiles.put(name, credentialTypes(types)));
        return profiles;
    }

    /**
     * Checks credential types as written in {@code signing} against the types tools declare —
     * {@code pgp4}, {@code pgp6} and {@code sigstore}, the spelling signer entries use — so that a
     * misspelled type fails the load instead of silently selecting no tool.
     */
    private static List<String> credentialTypes(List<String> written) {
        for (String name : written) {
            if (!SIGNING_CREDENTIAL_TYPES.contains(name)) {
                String suggestion = NearestName.among(name, SIGNING_CREDENTIAL_TYPES);
                throw new PolicyConfigException("signing: unknown credential type '" + name + "'"
                        + (suggestion == null ? "" : " — did you mean '" + suggestion + "'?")
                        + "; expected " + String.join(", ", SIGNING_CREDENTIAL_TYPES));
            }
        }
        return written;
    }

    // --- Top-level Tools Registry ---

    /**
     * Parses the top-level {@code tools} section into a {@link ToolsConfig} registry.
     * <p>
     * Each tool entry maps a tool name to its settings, each a single value or a list of single values. Only the shape is
     * checked here: which tools exist and which settings each accepts is known to the tool
     * factories, so tool and setting names are checked when tools are built.
     *
     * @param node the {@code tools} YAML node, or {@code null}
     * @return the parsed tool registry, or {@link ToolsConfig#EMPTY} if absent
     * @throws PolicyConfigException if the section, a tool entry or a setting has the wrong shape
     */
    private static ToolsConfig parseToolsRegistry(JsonNode node) {
        if (node == null || node.isNull()) {
            return ToolsConfig.EMPTY;
        }
        requireMapping(node, "'tools'");
        Map<String, ToolConfig> result = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            result.put(entry.getKey(), parseToolConfig(entry.getKey(), entry.getValue()));
        }
        return new ToolsConfig(result);
    }

    private static ToolConfig parseToolConfig(String toolName, JsonNode node) {
        if (node.isNull()) {
            return new ToolConfig(Map.of());
        }
        String location = "tools." + toolName;
        if (!node.isObject()) {
            throw new PolicyConfigException(location + " must be a mapping of settings, not " + describe(node));
        }
        Map<String, String> settings = new LinkedHashMap<>();
        Set<String> lists = new LinkedHashSet<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            JsonNode value = entry.getValue();
            String settingLocation = location + "." + entry.getKey();
            if (value.isArray()) {
                settings.put(entry.getKey(), joinListItems(value, settingLocation));
                lists.add(entry.getKey());
            } else if (!value.isValueNode() || value.isNull()) {
                throw new PolicyConfigException(settingLocation
                        + " must be a single value, not " + describe(value));
            } else {
                settings.put(entry.getKey(), value.asString());
            }
        }
        return new ToolConfig(settings, lists);
    }

    private static String joinListItems(JsonNode list, String location) {
        List<String> items = new ArrayList<>();
        for (JsonNode item : list) {
            if (!item.isValueNode() || item.isNull()) {
                throw new PolicyConfigException(location + ": list items must be single values, not "
                        + describe(item));
            }
            items.add(item.asString());
        }
        return String.join(ToolSetting.LIST_SEPARATOR, items);
    }

    // --- Trust Policy (rules / defaults) ---

    /**
     * Parses the {@code rules} and {@code defaults} sections into a raw {@link TrustPolicySpec}.
     * <p>
     * This is structural only: {@code match} entries are resolved against the artifact-set names or
     * parsed as patterns, {@code requires} is normalized into a conjunction of disjunctions by
     * signer id, and the enforcement and extra-claims settings are read. Signer references are not
     * resolved and issuer assertability is not checked — those happen when the policy is compiled on
     * the verification path. The policy is {@linkplain TrustPolicySpec#declared() declared} when
     * the document declares {@code rules}, an empty list included; a file that only configures
     * signing, tools or signers is zero-config for verification, which observes rather than
     * enforces. {@code defaults} without {@code rules} is rejected: with no rule every artifact
     * is {@code NOT_CONFIGURED}, so defaults alone could only fail everything or change
     * nothing, and they must not switch enforcement on by themselves.
     *
     * @param root the document root
     * @param sets the parsed artifact-set registry, for {@code match} expansion
     * @param issuers the canonical default issuers
     * @return the raw trust policy spec
     * @throws PolicyConfigException if a rule, requirement, pattern or enforcement setting is
     *         structurally invalid, or {@code defaults} is declared without {@code rules}
     */
    private static TrustPolicySpec parseTrustPolicySpec(JsonNode root, ArtifactSetsConfig sets,
            List<String> issuers) {
        boolean declared = root.has("rules");
        JsonNode defaultsNode = root.get("defaults");
        if (!declared && defaultsNode != null) {
            throw new PolicyConfigException("'defaults' has no effect without 'rules': with no rule"
                    + " every artifact is NOT_CONFIGURED. Add 'rules' to declare a policy, or"
                    + " remove 'defaults'");
        }
        List<RuleSpec> rules = parseRules(root.get("rules"), sets);
        ClaimSetMode extraClaims = parseExtraClaims(defaultsNode);
        Map<ArtifactOutcome, EnforcementAction> defaults = parseDefaults(defaultsNode);
        return new TrustPolicySpec(rules, extraClaims, defaults, issuers, declared);
    }

    private static List<RuleSpec> parseRules(JsonNode node, ArtifactSetsConfig sets) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (!node.isArray()) {
            throw new PolicyConfigException("'rules' must be a list of rule objects");
        }
        List<RuleSpec> rules = new ArrayList<>();
        int index = 0;
        for (JsonNode ruleNode : node) {
            rules.add(parseRule(ruleNode, sets, "rules[" + index + "]"));
            index++;
        }
        return rules;
    }

    private static RuleSpec parseRule(JsonNode node, ArtifactSetsConfig sets, String location) {
        if (!node.isObject()) {
            throw new PolicyConfigException(location + " must be a rule object with 'match'");
        }
        List<ArtifactPattern> patterns = parseMatch(node.get("match"), sets, location);
        List<Set<String>> clauseIds = parseRequires(node.get("requires"), location);
        Map<ArtifactOutcome, EnforcementAction> enforcement = parseEnforcementOverrides(node, location);
        return new RuleSpec(patterns, clauseIds, enforcement, location, extraClaims(node, location));
    }

    private static List<ArtifactPattern> parseMatch(JsonNode node, ArtifactSetsConfig sets,
            String location) {
        if (node == null || node.isNull()) {
            throw new PolicyConfigException(location + ": a rule must declare 'match'");
        }
        List<String> entries = stringList(node, location + ".match");
        if (entries.isEmpty()) {
            throw new PolicyConfigException(
                    location + ": 'match' must list at least one artifact-set name or pattern");
        }
        List<ArtifactPattern> patterns = new ArrayList<>();
        for (String entry : entries) {
            List<String> expanded = sets.get(entry);
            if (expanded != null) {
                for (String pattern : expanded) {
                    patterns.add(ArtifactPattern.parse(pattern));
                }
            } else if (isBareWord(entry)) {
                throw new PolicyConfigException(undefinedSetMessage(entry, sets, location));
            } else {
                patterns.add(ArtifactPattern.parse(entry));
            }
        }
        return patterns;
    }

    /**
     * Indicates whether a {@code match} entry can only be an artifact-set reference.
     * <p>
     * A word with no {@code .}, {@code :} or {@code *} reads equally as a set name and as a
     * one-word group, so a misspelled set would silently become a group pattern matching nothing.
     * Such a word is therefore always a set reference, and a one-word group is written with an
     * artifact wildcard, {@code junit:*}.
     */
    private static boolean isBareWord(String entry) {
        return entry.indexOf('.') < 0 && entry.indexOf(':') < 0 && entry.indexOf('*') < 0;
    }

    private static String undefinedSetMessage(String entry, ArtifactSetsConfig sets,
            String location) {
        String suggestion = NearestName.among(entry, sets.names());
        return location + ": '" + entry + "' is not a defined artifact-set"
                + (suggestion == null ? "" : " — did you mean '" + suggestion + "'?")
                + "; to match a one-word group, write '" + entry + ":*'";
    }

    private static List<Set<String>> parseRequires(JsonNode node, String location) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (node.isString()) {
            return List.of(Set.of(signerReference(node, location)));
        }
        if (!node.isArray()) {
            throw new PolicyConfigException(location
                    + ": 'requires' must be a signer id or a list of clauses, not " + describe(node));
        }
        if (node.isEmpty()) {
            throw new PolicyConfigException(location + ": 'requires' must not be empty; to tolerate"
                    + " an artifact relax enforcement, e.g. 'on-no-claim: ignore'");
        }
        List<Set<String>> clauses = new ArrayList<>();
        for (JsonNode clauseNode : node) {
            clauses.add(parseClause(clauseNode, location));
        }
        return clauses;
    }

    private static Set<String> parseClause(JsonNode node, String location) {
        if (node.isString()) {
            return Set.of(signerReference(node, location));
        }
        if (node.isObject()) {
            return parseAnyOfClause(node, location);
        }
        throw new PolicyConfigException(location
                + ": a requirement clause must be a signer id or '{any-of: [...]}'");
    }

    private static Set<String> parseAnyOfClause(JsonNode node, String location) {
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            if (!"any-of".equals(field.getKey())) {
                throw new PolicyConfigException(location + ": unknown key '" + field.getKey()
                        + "' in a requirement clause; expected a signer id or 'any-of'");
            }
        }
        JsonNode anyOf = node.get("any-of");
        if (anyOf == null || !anyOf.isArray() || anyOf.isEmpty()) {
            throw new PolicyConfigException(location
                    + ": 'any-of' must list at least one signer id");
        }
        Set<String> ids = new LinkedHashSet<>();
        for (JsonNode element : anyOf) {
            ids.add(anyOfEntry(element, location));
        }
        return ids;
    }

    /**
     * Reads one {@code any-of} entry. A requirement is a conjunction of disjunctions, so an entry
     * is a signer id and nothing deeper: a mapping or a nested {@code any-of} has no meaning.
     */
    private static String anyOfEntry(JsonNode element, String location) {
        if (element.isObject() && element.has("any-of")) {
            throw new PolicyConfigException(location
                    + ": nested 'any-of' is not supported; list the signers in one 'any-of'");
        }
        if (!element.isValueNode() || element.isNull()) {
            throw new PolicyConfigException(location + ": 'any-of' entries must be signer ids; found "
                    + describe(element));
        }
        return signerReference(element, location);
    }

    private static String signerReference(JsonNode node, String location) {
        String id = node.asString();
        if (id.isBlank()) {
            throw new PolicyConfigException(location
                    + ": a signer reference must not be blank");
        }
        return id;
    }

    private static String describe(JsonNode node) {
        if (node.isObject()) {
            return "a mapping";
        }
        if (node.isArray()) {
            return "a list";
        }
        return node.isNull() ? "an empty value" : "'" + node.asString() + "'";
    }

    private static Map<ArtifactOutcome, EnforcementAction> parseEnforcementOverrides(JsonNode node,
            String location) {
        Map<ArtifactOutcome, EnforcementAction> enforcement = new EnumMap<>(ArtifactOutcome.class);
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            String key = field.getKey();
            if ("match".equals(key) || "requires".equals(key) || EXTRA_CLAIMS.equals(key)) {
                continue;
            }
            if (!key.startsWith("on-")) {
                throw new PolicyConfigException(location + ": unknown key '" + key
                        + "'; expected 'match', 'requires', 'extra-claims' or an 'on-*' enforcement"
                        + " override");
            }
            enforcement.put(outcomeForEnforcementKey(key, location),
                    EnforcementAction.parse(field.getValue().asString()));
        }
        return enforcement;
    }

    private static ClaimSetMode parseExtraClaims(JsonNode defaultsNode) {
        if (defaultsNode == null || defaultsNode.isNull()) {
            return ClaimSetMode.ALL_CLAIMS;
        }
        ClaimSetMode mode = extraClaims(defaultsNode, "defaults");
        return mode == null ? ClaimSetMode.ALL_CLAIMS : mode;
    }

    /**
     * Reads an {@code extra-claims} setting, in {@code defaults} or on a rule.
     *
     * @return the mode, or {@code null} when the node does not set one
     */
    private static ClaimSetMode extraClaims(JsonNode node, String location) {
        String value = textField(node, EXTRA_CLAIMS);
        if (value == null) {
            return null;
        }
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "reject" -> ClaimSetMode.ALL_CLAIMS;
            case "ignore" -> ClaimSetMode.ANY_CLAIM;
            default -> throw new PolicyConfigException(location + ": 'extra-claims' must be 'reject'"
                    + " or 'ignore', not '" + value + "'");
        };
    }

    private static Map<ArtifactOutcome, EnforcementAction> parseDefaults(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        if (!node.isObject()) {
            throw new PolicyConfigException("'defaults' must be a mapping");
        }
        Map<ArtifactOutcome, EnforcementAction> defaults = new EnumMap<>(ArtifactOutcome.class);
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            String key = field.getKey();
            if (EXTRA_CLAIMS.equals(key)) {
                continue;
            }
            if (!key.startsWith("on-")) {
                throw new PolicyConfigException("defaults: unknown key '" + key
                        + "'; expected 'extra-claims' or an 'on-*' enforcement default");
            }
            defaults.put(outcomeForEnforcementKey(key, "defaults"),
                    EnforcementAction.parse(field.getValue().asString()));
        }
        return defaults;
    }

    private static ArtifactOutcome outcomeForEnforcementKey(String key, String location) {
        return switch (key) {
            case "on-unsatisfied" -> ArtifactOutcome.UNSATISFIED;
            case "on-no-claim" -> ArtifactOutcome.NO_CLAIM;
            case "on-indeterminate" -> ArtifactOutcome.INDETERMINATE;
            case "on-not-configured" -> ArtifactOutcome.NOT_CONFIGURED;
            case "on-failed" -> throw new PolicyConfigException(location
                    + ": FAILED is always 'fail' and cannot be overridden; remove 'on-failed'");
            case "on-satisfied" -> throw new PolicyConfigException(location
                    + ": SATISFIED has no enforcement; remove 'on-satisfied'");
            default -> throw new PolicyConfigException(location + ": unknown enforcement override '"
                    + key + "'");
        };
    }

    // --- Artifact Groups ---

    private static ArtifactSetsConfig parseArtifactGroups(JsonNode node) {
        if (node != null && !node.isNull()) {
            requireMapping(node, "'artifact-sets'");
        }
        return new ArtifactSetsConfig(stringListMap(node, "artifact-sets"));
    }

    private static Map<String, List<String>> stringListMap(JsonNode node, String location) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            result.put(entry.getKey(), stringList(entry.getValue(), location + "." + entry.getKey()));
        }
        return result;
    }

    // --- Verification ---

    private static final List<String> VERIFICATION_KEYS = List.of("toolchain", "resolve-signers",
            "import-to-keyring", "keyservers");

    /**
     * Parses the {@code verification} section into a {@link VerificationConfig}.
     * <p>
     * Contains operational concerns: key fetching behavior, keyserver URLs,
     * and the verification toolchain priority. Unknown keys and values of the wrong shape are
     * errors, as in the policy sections.
     *
     * @param node the {@code verification} YAML node, or {@code null}
     * @return the parsed verification configuration
     * @throws PolicyConfigException if the section has an unknown key or a value of the wrong shape
     */
    private static VerificationConfig parseVerificationConfig(JsonNode node) {
        if (node == null || node.isNull()) {
            return VerificationConfig.DEFAULT;
        }
        checkSection(node, "verification", VERIFICATION_KEYS);
        boolean resolveSigners = flag(node, "resolve-signers", true);
        boolean importToKeyring = flag(node, "import-to-keyring", false);
        List<String> keyservers = stringList(node.get("keyservers"), "verification.keyservers");
        JsonNode tcNode = node.get("toolchain");
        List<String> toolchain = (tcNode != null && !tcNode.isNull())
                ? stringList(tcNode, "verification.toolchain")
                : null;
        return new VerificationConfig(resolveSigners, importToKeyring, keyservers, toolchain);
    }

    // --- Utilities ---

    /**
     * Reads a value written as one string or a list of them.
     *
     * @param node the value, or {@code null} when absent
     * @param location where the value is, for the error message
     * @return the strings, empty when the value is absent or an empty string
     * @throws PolicyConfigException if the value or one of its entries is a mapping or a list
     */
    private static List<String> stringList(JsonNode node, String location) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (node.isValueNode()) {
            String text = node.asString();
            return text.isEmpty() ? List.of() : List.of(text);
        }
        if (!node.isArray()) {
            throw notAStringList(location, node);
        }
        List<String> result = new ArrayList<>();
        for (JsonNode el : node) {
            if (el.isContainer()) {
                throw notAStringList(location, el);
            }
            if (!el.isNull()) {
                result.add(el.asString());
            }
        }
        return Collections.unmodifiableList(result);
    }

    private static PolicyConfigException notAStringList(String location, JsonNode node) {
        return new PolicyConfigException(location + " must be a string or a list of strings, not "
                + describe(node));
    }

    private static String textField(JsonNode node, String field) {
        JsonNode child = node.get(field);
        return child != null && !child.isNull() && child.isValueNode() ? child.asString() : null;
    }

    private static boolean flag(JsonNode node, String field, boolean defaultValue) {
        JsonNode child = node.get(field);
        if (child == null || child.isNull()) {
            return defaultValue;
        }
        if (!child.isBoolean()) {
            throw new PolicyConfigException("verification." + field + " must be true or false, not "
                    + describe(child));
        }
        return child.booleanValue();
    }

    /**
     * Checks that a section is a mapping whose keys the schema defines.
     *
     * @param node the section
     * @param section the section's key, for the error message
     * @param known the keys the section accepts
     * @throws PolicyConfigException naming the nearest known key, if any
     */
    private static void checkSection(JsonNode node, String section, List<String> known) {
        requireMapping(node, "'" + section + "'");
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            String key = field.getKey();
            if (!known.contains(key)) {
                String suggestion = NearestName.among(key, known);
                throw new PolicyConfigException(section + ": unknown key '" + key + "'"
                        + (suggestion == null
                                ? "; expected one of " + String.join(", ", known)
                                : " — did you mean '" + suggestion + "'?"));
            }
        }
    }

    private static void requireMapping(JsonNode node, String what) {
        if (!node.isObject()) {
            throw new PolicyConfigException(what + " must be a mapping, not " + describe(node));
        }
    }

}
