package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.JsonNode;

/**
 * The published schema and Sigmund agree on what a {@code sigmund.yaml} may contain.
 *
 * <p>
 * Sigmund stays authoritative: the schema cannot see signer references, rule ties or issuer
 * assertability, and is never consulted at runtime. What it does state — keys, value shapes, the
 * names of tools, settings, credential types and identity attributes — must not drift from what
 * Sigmund accepts, or an editor would flag a working file or complete a key Sigmund rejects.
 * Valid documents pass both; every structurally invalid document Sigmund rejects — when it loads
 * the file, compiles the policy or checks the tool settings — the schema rejects too. Every
 * documented example is checked against the schema by {@link DocumentationExamplesTest}.
 */
class SchemaAgreementTest {

    /**
     * Loads a document the way Sigmund does on the verification path: parse, compile the policy
     * when there is one, and check tool names and settings against the tool factories.
     */
    private static void load(String yaml) {
        SigmundConfig config = SigmundConfigParser.parse("<fixture>", new StringReader(yaml));
        if (!config.trustPolicySpec().rules().isEmpty()) {
            RulePolicy.compile(config.trustPolicySpec(), config.signers());
        }
        Sigmund.builder().config(config).checkToolConfiguration();
    }

    static Stream<String> validDocuments() {
        return Stream.of(
                "",
                "rules: []",
                "tools: { gpg: { passphrase-env: 0x12345678, executable: 0123 } }",
                "tools: { bc: { signing-fingerprint: [\"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\", \"BBE7232D7991050B54C8EA0ADC08637CA615D22C\"] } }",
                "tools: { sq: { signing-fingerprint: [\"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\", \"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"] } }",
                "tools: { sq: { signing-fingerprint: \"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\" } }",
                "tools: { gpg: { signing-fingerprint: [\"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\", \"BBE7232D7991050B54C8EA0ADC08637CA615D22C\"] } }",
                """
                        issuers: [keys.openpgp.org, "https://token.actions.githubusercontent.com"]
                        signers:
                          minimal: "dev@example.com"
                          rotated:
                            pgp4: ["4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12", "BBE7232D7991050B54C8EA0ADC08637CA615D22C"]
                            pgp6: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                            email: "rotated@example.com"
                          ci:
                            identities:
                              - issuer: "https://token.actions.githubusercontent.com"
                                source-repository-uri: "https://github.com/org/repo"
                                build-trigger: release
                          org:
                            members:
                              - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
                                email: "a@example.com"
                              - identities: [{ email: "b@example.com" }]
                        artifact-sets:
                          stack: [org.example.*, "org.other:lib"]
                          single: org.single
                        rules:
                          - match: stack
                            requires: [rotated, { any-of: [ci, org] }]
                            extra-claims: ignore
                            on-indeterminate: warn
                          - match: [single, "com.acme:*"]
                            requires: minimal
                          - match: ["com.internal:util"]
                            on-no-claim: ignore
                        defaults:
                          extra-claims: reject
                          on-unsatisfied: fail
                          on-no-claim: warn
                          on-indeterminate: fail
                          on-not-configured: warn
                        signing:
                          signer: rotated
                          toolchain: [bc, sq]
                          credential-types: [pgp4, pgp6]
                          profiles:
                            classic: [pgp4]
                            keyless: sigstore
                        verification:
                          toolchain: [bc, sq, gpg]
                          resolve-signers: true
                          import-to-keyring: false
                          keyservers: hkps://keys.openpgp.org
                        tools:
                          bc:
                            gnupg-home: /tmp/gnupg
                            cipher-suite: ed448
                          sq:
                          gpg:
                            home: /tmp/gnupg
                            signing-fingerprint: "4aee18f83afdeb23468b2e5a2d7baf3c1e9f5a12"
                        """);
    }

    static Stream<String> structurallyInvalidDocuments() {
        return Stream.of(
                "colour: red",
                "rules: { match: org.example }",
                "rules: [{ requires: alice }]",
                "rules: [{ match: [] }]",
                "rules: [{ match: org.example, requires: [] }]",
                "rules: [{ match: org.example, requires: { any-of: [a] } }]",
                "rules: [{ match: org.example, requires: [{ any-of: [] }] }]",
                "rules: [{ match: org.example, requires: [{ all-of: [a] }] }]",
                "rules: [{ match: org.example, requires: [{ any-of: [{ any-of: [a] }] }] }]",
                "rules: [{ match: org.example, on-failed: ignore }]",
                "rules: [{ match: org.example, on-satisfied: ignore }]",
                "rules: [{ match: org.example, on-no-claim: maybe }]",
                "rules: [{ match: org.example, extra-claims: some }]",
                "rules: [{ match: org.example, colour: red }]",
                "defaults: { on-no-claim: warn }",
                "{ rules: [], defaults: { colour: red } }",
                "{ rules: [], defaults: [warn] }",
                "issuers: { github: x }",
                "signers: { a: [dev@example.com] }",
                "signers: { a: \"\" }",
                "signers: { a: {} }",
                "signers: { a: { pgp4: ABC } }",
                "signers: { a: { pgp4: \"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\" } }",
                "signers: { a: { pgp6: \"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\" } }",
                "signers: { a: { pgp4: { fp: \"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\" } } }",
                "signers: { a: { fingerprint: \"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\" } }",
                "signers: { a: { email: [dev@example.com] } }",
                "signers: { a: { identities: { email: dev@example.com } } }",
                "signers: { a: { identities: [{ issuer: keys.openpgp.org }] } }",
                "signers: { a: { members: { email: dev@example.com } } }",
                "signers: { a: { members: [{ members: [{ email: dev@example.com }] }] } }",
                "signers: { a: { members: [{ colour: red }] } }",
                """
                        signers: { a: { identities: [{ issuer: "https://token.actions.githubusercontent.com", source-repo-uri: x }] } }
                        rules: [{ match: org.example, requires: a }]
                        """,
                "artifact-sets: { stack: [{ group: org.apache }] }",
                "artifact-sets: [org.apache]",
                "signing: [bc]",
                "signing: { toolchian: [bc] }",
                "signing: { signer: [alice] }",
                "signing: { toolchain: [bcc] }",
                "signing: { credential-types: [openpgp4] }",
                "signing: { profiles: [pgp4] }",
                "signing: { profiles: { hybrid: [pgp4, pqc] } }",
                "verification: { resolve-signer: false }",
                "verification: { resolve-signers: \"true\" }",
                "verification: { resolve-signers: yes }",
                "verification: { keyservers: { url: hkps://keys.openpgp.org } }",
                "verification: { toolchain: [bcc] }",
                "tools: [bc]",
                "tools: { bc: [gnupg-home] }",
                "tools: { bc: { gnupg-home: [/a, /b] } }",
                "tools: { sq: { signing-fingerprint: [] } }",
                "tools: { sq: { signing-fingerprint: \"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12,BBE7232D7991050B54C8EA0ADC08637CA615D22C\" } }",
                "tools: { bc: { signing-fingerprint: [\"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\", DEADBEEF] } }",
                "tools: { sq: { signing-fingerprint: [\"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\", \"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\"] } }",
                "tools: { gpg: { signing-fingerprint: \"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\" } }",
                "tools: { gpg: { signing-fingerprint: [\"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\", \"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"] } }",
                "tools: { sqq: { home: /tmp/sq } }",
                "tools: { bc: { gnupg-hom: /tmp/gnupg } }",
                "tools: { bc: { credentials: pgp4 } }",
                "tools: { sq: { gnupg-home: /tmp/gnupg } }",
                "tools: { gpg: { key-name: \"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12\" } }",
                "tools: { gpg: { signing-fingerprint: \"0xDEADBEEF\" } }",
                "tools: { sq: { signing-fingerprint: \"alice@example.com\" } }",
                "tools: { bc: { signing-fingerprint: \"4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A\" } }");
    }

    @ParameterizedTest
    @MethodSource("validDocuments")
    void aValidDocumentPassesBoth(String yaml) {
        load(yaml);

        assertThat(ConfigSchema.errors(yaml)).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("structurallyInvalidDocuments")
    void aStructurallyInvalidDocumentFailsBoth(String yaml) {
        assertThatThrownBy(() -> load(yaml)).isInstanceOf(PolicyConfigException.class);

        assertThat(ConfigSchema.errors(yaml)).isNotEmpty();
    }

    /**
     * The names the schema offers for completion are the names Sigmund accepts.
     */
    @Nested
    class Vocabulary {

        @Test
        void eachBuiltInToolAcceptsTheSettingsTheSchemaLists() {
            for (SignatureToolFactory factory : List.of(new BcToolFactory(), new GpgToolFactory(),
                    new SqToolFactory())) {
                assertThat(propertyNames(tool(factory.toolName())))
                        .as("schema settings of %s", factory.toolName())
                        .containsExactlyInAnyOrderElementsOf(factory.acceptedSettings());
            }
        }

        /** Sigstore's settings are checked in its own module, which can see its factory. */
        @Test
        void theSchemaListsTheBuiltInToolsAndSigstore() {
            Set<String> tools = propertyNames(ConfigSchema.JSON.at("/properties/tools"));

            assertThat(tools).containsExactlyInAnyOrder("bc", "gpg", "sq", "sigstore");
            assertThat(enumValues(ConfigSchema.JSON.at("/$defs/toolName"))).isEqualTo(tools);
        }

        @Test
        void credentialTypesAreTheTypesToolsProduce() {
            assertThat(enumValues(ConfigSchema.JSON.at("/$defs/credentialType")))
                    .containsExactlyInAnyOrder(Credential.TYPE_PGP4, Credential.TYPE_PGP6,
                            Credential.TYPE_SIGSTORE);
        }

        @Test
        void identityAttributesAreWhatSomeIssuerKindAttests() {
            Set<String> attributes = new HashSet<>();
            for (IssuerKind kind : IssuerKind.values()) {
                attributes.addAll(kind.attributes());
            }

            Set<String> listed = new HashSet<>(propertyNames(ConfigSchema.JSON.at("/$defs/identity")));
            listed.remove("issuer");
            assertThat(listed).isEqualTo(attributes);
        }

        private JsonNode tool(String name) {
            return ConfigSchema.JSON.at("/properties/tools/properties/" + name);
        }

        private Set<String> propertyNames(JsonNode node) {
            JsonNode properties = node.get("properties");
            assertThat(properties).as("properties of %s", node).isNotNull();
            Set<String> names = new HashSet<>();
            names.addAll(properties.propertyNames());
            return names;
        }

        private Set<String> enumValues(JsonNode node) {
            List<String> values = new ArrayList<>();
            node.get("enum").forEach(value -> values.add(value.asString()));
            return new HashSet<>(values);
        }
    }
}
