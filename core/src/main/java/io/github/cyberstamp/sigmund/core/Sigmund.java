package io.github.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The central facade for Sigmund — tool registry, signature verification, and session creation.
 *
 * <h3>Usage from config file</h3>
 *
 * <pre>{@code
 * SigmundConfig config = SigmundConfig.parse(Path.of("sigmund.yaml"));
 * Sigmund sigmund = Sigmund.builder()
 *         .config(config)
 *         .build();
 *
 * // Sign (default profile or all tools)
 * Signer signer = sigmund.signer();
 * // Sign (named profile)
 * Signer v6Signer = sigmund.signer("v6-only");
 * SigningOutput output = signer.sign(artifact, outputDir);
 *
 * // Verify trust
 * TrustVerifier verifier = sigmund.verifier(config.trustPolicy());
 * TrustResult result = verifier.assess(artifact, artifactFile, evidenceFiles);
 * }</pre>
 *
 * <h3>Programmatic construction</h3>
 *
 * <pre>{@code
 * Sigmund sigmund = Sigmund.builder()
 *         .addTool(new GpgRunner("mykey"))
 *         .addTool(new SqRunner("sq", sqHome, fingerprint))
 *         .build();
 * }</pre>
 *
 * <h3>Verify-only</h3>
 *
 * <pre>{@code
 * Sigmund sigmund = Sigmund.builder().build();
 * SignatureVerificationReport report = sigmund.verify(artifactFile, signatureFile);
 * }</pre>
 *
 * @see Signer
 * @see TrustVerifier
 */
public class Sigmund {

    private final List<SignatureTool> tools;
    private final List<EvidenceProvider> evidenceProviders;
    private final SigningConfig signingConfig;
    private final List<SignatureFormat> formats;

    private Sigmund(List<SignatureTool> tools, List<SignatureFormat> formats,
            List<EvidenceProvider> evidenceProviders, SigningConfig signingConfig) {
        if (tools.isEmpty()) {
            throw new SigmundException("No tools available");
        }
        this.tools = tools;
        this.formats = formats;
        this.evidenceProviders = evidenceProviders;
        this.signingConfig = signingConfig;
    }

    /**
     * Creates a new builder.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a signer using the default profile (if configured) or all signing tools.
     *
     * @return a new signer
     */
    public Signer signer() {
        if (signingConfig != null && signingConfig.defaultProfile() != null) {
            return signer(signingConfig.defaultProfile());
        }
        List<SignatureTool> signingTools = tools.stream()
                .filter(SignatureTool::canSign)
                .toList();
        return new Signer(signingTools);
    }

    /**
     * Creates a signer using a named profile from the signing configuration.
     * <p>
     * The profile maps to a list of credential types; only tools whose
     * {@link SignatureTool#supportedCredentialTypes()} intersects with the
     * profile's credential types are included.
     *
     * @param profileName the profile name (e.g., {@code "hybrid"}, {@code "v6-only"})
     * @return a new signer filtered to the profile's credential types
     * @throws SigmundException if the profile name is not found in the signing config
     */
    public Signer signer(String profileName) {
        if (signingConfig == null || signingConfig.profiles().isEmpty()) {
            throw new SigmundException("No signing profiles configured");
        }
        List<String> credentialTypes = signingConfig.profiles().get(profileName);
        if (credentialTypes == null) {
            throw new SigmundException("Unknown signing profile: " + profileName
                    + ". Available profiles: " + signingConfig.profiles().keySet());
        }
        List<SignatureTool> profileTools = tools.stream()
                .filter(SignatureTool::canSign)
                .filter(t -> t.supportedCredentialTypes().stream()
                        .anyMatch(credentialTypes::contains))
                .toList();
        return new Signer(profileTools);
    }

    /**
     * Creates a trust verifier using the given policy.
     * <p>
     * The {@link ToolsConfig} set at build time is used for key fetching.
     *
     * @param policy the trust policy to apply
     * @return a new trust verifier
     */
    public TrustVerifier verifier(TrustPolicy policy) {
        return new TrustVerifier(policy, evidenceProviders);
    }

    /**
     * Verifies a single signature file against an artifact (no trust policy).
     *
     * @param artifactFile the artifact that was signed
     * @param signatureFile the signature file to verify
     * @return the verification report
     */
    public SignatureVerificationReport verify(Path artifactFile, Path signatureFile) {
        return verifyAll(artifactFile, List.of(signatureFile));
    }

    /**
     * Verifies multiple signature files against an artifact (no trust policy).
     *
     * @param artifactFile the artifact that was signed
     * @param signatureFiles the signature files to verify
     * @return the verification report
     */
    public SignatureVerificationReport verifyAll(Path artifactFile, List<Path> signatureFiles) {
        List<FileSignatureReport> fileReports = new ArrayList<>(signatureFiles.size());
        for (Path sigFile : signatureFiles) {
            fileReports.add(verifySingleFile(artifactFile, sigFile));
        }
        return new SignatureVerificationReport(fileReports);
    }

    /**
     * Returns all registered tools.
     *
     * @return an unmodifiable list of tools
     */
    public List<SignatureTool> tools() {
        return tools;
    }

    /**
     * Returns a tool by name.
     *
     * @param name the tool name
     * @return the tool, or {@code null} if not found
     */
    public SignatureTool tool(String name) {
        for (SignatureTool tool : tools) {
            if (tool.name().equals(name)) {
                return tool;
            }
        }
        return null;
    }

    /**
     * Finds the first tool implementing the given capability interface.
     *
     * @param capability the capability interface class (e.g., {@code KeyGenerator.class})
     * @param <T> the capability type
     * @return the tool cast to the capability, or {@code null} if none found
     */
    public <T> T findTool(Class<T> capability) {
        for (SignatureTool tool : tools) {
            if (capability.isInstance(tool)) {
                return capability.cast(tool);
            }
        }
        return null;
    }

    /**
     * Finds a tool implementing the given capability with a specific name.
     *
     * @param capability the capability interface class
     * @param toolName the tool name to match
     * @param <T> the capability type
     * @return the tool cast to the capability, or {@code null} if not found
     */
    public <T> T findTool(Class<T> capability, String toolName) {
        for (SignatureTool tool : tools) {
            if (tool.name().equals(toolName) && capability.isInstance(tool)) {
                return capability.cast(tool);
            }
        }
        return null;
    }

    private FileSignatureReport verifySingleFile(Path artifactFile, Path signatureFile) {
        SignatureFormat format = findFormat(signatureFile);
        if (format == null) {
            return new FileSignatureReport(signatureFile, "unknown", List.of());
        }
        List<VerificationUnit> units = format.parse(signatureFile);
        List<VerifyResult> results = new ArrayList<>();
        for (VerificationUnit unit : units) {
            VerifyResult result = verifyUnit(artifactFile, unit);
            if (result != null) {
                results.add(result);
            }
        }
        return new FileSignatureReport(signatureFile, format.name(), results);
    }

    private SignatureFormat findFormat(Path signatureFile) {
        for (SignatureFormat format : formats) {
            if (format.canHandle(signatureFile)) {
                return format;
            }
        }
        return null;
    }

    private VerifyResult verifyUnit(Path artifactFile, VerificationUnit unit) {
        for (SignatureTool tool : tools) {
            if (!tool.canVerify(unit)) {
                continue;
            }
            VerifyResult result = tool.verify(artifactFile, unit);
            if (result.verdict() != Verdict.SKIPPED) {
                return result;
            }
        }
        return null;
    }

    /**
     * Builder for constructing a {@link Sigmund} instance.
     * <p>
     * {@link #build()} always initializes tools from registered factories based on the
     * {@link ToolsConfig}. Explicit {@link #addTool(SignatureTool)} calls take precedence.
     * {@link #config(SigmundConfig)} applies the full config including signing and tool settings.
     * {@link #toolsConfig(ToolsConfig)} sets key fetching and tool config.
     */
    public static class Builder {

        private final List<SignatureTool> tools = new ArrayList<>(2);
        private final List<EvidenceProvider> extraProviders = new ArrayList<>();
        private ToolsConfig toolsConfig = ToolsConfig.DEFAULT;
        private SigningConfig signingConfig;
        private PassphraseProvider bcPassphraseProvider;

        /**
         * Sets key fetching and keyserver configuration, fixed at build time.
         * All {@link TrustVerifier} instances created from this {@link Sigmund} share it.
         *
         * @param dc the discovery configuration
         * @return this builder
         */
        public Builder toolsConfig(ToolsConfig dc) {
            this.toolsConfig = dc != null ? dc : ToolsConfig.DEFAULT;
            return this;
        }

        /**
         * Applies the full configuration.
         * <p>
         * Overrides any prior {@code toolsConfig()} call.
         * Explicit {@code addTool()} calls take precedence over initialized tools.
         *
         * @param config the unified configuration
         * @return this builder
         */
        public Builder config(SigmundConfig config) {
            this.toolsConfig = config.toolsConfig();
            this.signingConfig = config.signingConfig();
            return this;
        }

        /**
         * Sets the passphrase provider for the BC signing tool.
         * Takes precedence over environment variable and console fallback.
         *
         * <p>
         * This exists as a dedicated setter rather than a key in the
         * {@code Map<String, String>} settings because passphrases must
         * stay as {@code char[]} throughout their lifecycle. Routing a
         * passphrase through a String-valued map would create an immutable
         * {@code String} on the heap that cannot be zeroed after use,
         * defeating the {@code char[]}-based zeroing in
         * {@link PassphraseProvider} and {@link BcRunner}.
         *
         * @param provider the passphrase provider
         * @return this builder
         */
        public Builder bcPassphraseProvider(PassphraseProvider provider) {
            this.bcPassphraseProvider = provider;
            return this;
        }

        /**
         * Adds or replaces a {@link SignatureTool} by {@link SignatureTool#name()}.
         *
         * @param tool the tool to add
         * @return this builder
         * @throws SigmundException if the tool is not available
         */
        public Builder addTool(SignatureTool tool) {
            if (!tool.isAvailable()) {
                throw new SigmundException(
                        "Tool '" + tool.name() + "' is not available");
            }
            String name = tool.name();
            tools.removeIf(t -> t.name().equals(name));
            tools.add(tool);
            return this;
        }

        /**
         * Creates and adds a verify-only tool using the registered factory.
         *
         * @param toolName the tool name (e.g., {@code "gpg"}, {@code "sq"})
         * @param settings tool-specific configuration settings
         * @return this builder
         * @throws SigmundException if no factory is registered for the tool name,
         *         or the tool is not available
         */
        public Builder addTool(String toolName, Map<String, String> settings) {
            return addTool(createFromFactory(toolName, false, settings));
        }

        /**
         * Creates and adds a signing-capable tool using the registered factory.
         * <p>
         * The factory handles defaults; only provide settings the user has explicitly
         * configured (e.g., {@code "key-name"}, {@code "signing-fingerprint"}, {@code "home"}).
         *
         * @param toolName the tool name (e.g., {@code "gpg"}, {@code "sq"})
         * @param settings tool-specific configuration settings
         * @return this builder
         * @throws SigmundException if no factory is registered for the tool name,
         *         or the tool is not available
         */
        public Builder addSigningTool(String toolName, Map<String, String> settings) {
            return addTool(createFromFactory(toolName, true, settings));
        }

        private SignatureTool createFromFactory(String toolName, boolean signing,
                Map<String, String> settings) {
            for (SignatureToolFactory factory : FACTORIES) {
                if (factory.toolName().equals(toolName)) {
                    if (signing && factory instanceof BcToolFactory bcFactory
                            && bcPassphraseProvider != null) {
                        return bcFactory.create(null, settings, bcPassphraseProvider);
                    }
                    return signing
                            ? factory.create(null, settings)
                            : factory.createVerifyOnly(settings);
                }
            }
            throw new SigmundException("Unknown tool: " + toolName);
        }

        /**
         * Adds a non-signature {@link EvidenceProvider} (e.g., SLSA attestation verifier).
         *
         * @param provider the evidence provider
         * @return this builder
         */
        public Builder addEvidenceProvider(EvidenceProvider provider) {
            extraProviders.add(provider);
            return this;
        }

        /**
         * Builds the {@link Sigmund} instance.
         * <p>
         * Initializes tools from registered factories based on {@link ToolsConfig}.
         * Explicit {@link #addTool} calls take precedence — already-added tools are skipped.
         *
         * @return the configured Sigmund instance
         * @throws SigmundException if no tools are available
         */
        public Sigmund build() {
            initializeTools();

            Map<String, List<SignatureTool>> toolsByFormat = new LinkedHashMap<>(2);
            for (SignatureTool tool : tools) {
                toolsByFormat.computeIfAbsent(tool.signatureFormat().name(), k -> new ArrayList<>(2))
                        .add(tool);
            }

            List<SignatureFormat> formats = new ArrayList<>(toolsByFormat.size());
            List<EvidenceProvider> providers = new ArrayList<>(toolsByFormat.size() + extraProviders.size());
            for (List<SignatureTool> group : toolsByFormat.values()) {
                SignatureFormat format = group.get(0).signatureFormat();
                formats.add(format);
                providers.add(new SignatureEvidenceAdapter(format, group, toolsConfig));
            }
            for (EvidenceProvider ep : extraProviders) {
                if (ep.isAvailable()) {
                    providers.add(ep);
                }
            }

            return new Sigmund(List.copyOf(tools), List.copyOf(formats),
                    List.copyOf(providers), signingConfig);
        }

        private static final List<SignatureToolFactory> FACTORIES = List.of(
                new BcToolFactory(), new GpgToolFactory(), new SqToolFactory());

        private void initializeTools() {
            Map<String, Map<String, String>> toolSettings = toolsConfig.tools();
            List<String> priority = toolsConfig.effectiveToolPriority();
            for (String toolName : priority) {
                if (findByName(toolName) != null) {
                    continue;
                }
                initializeTool(toolName, toolSettings);
            }
            if (toolsConfig.toolPriority() == null) {
                for (SignatureToolFactory factory : FACTORIES) {
                    if (findByName(factory.toolName()) == null
                            && !priority.contains(factory.toolName())) {
                        initializeTool(factory.toolName(), toolSettings);
                    }
                }
            }
        }

        private void initializeTool(String toolName, Map<String, Map<String, String>> toolSettings) {
            for (SignatureToolFactory factory : FACTORIES) {
                if (!factory.toolName().equals(toolName)) {
                    continue;
                }
                Map<String, String> settings = toolSettings.getOrDefault(toolName, Map.of());
                try {
                    SignatureTool tool = factory.createVerifyOnly(settings);
                    if (tool.isAvailable()) {
                        tools.add(tool);
                    }
                } catch (SigmundException e) {
                    System.getLogger(Sigmund.class.getName())
                            .log(System.Logger.Level.DEBUG,
                                    "Skipping tool '" + toolName + "': " + e.getMessage());
                }
                return;
            }
            System.getLogger(Sigmund.class.getName())
                    .log(System.Logger.Level.WARNING,
                            "Unknown tool '" + toolName + "' in tool-priority");
        }

        private SignatureTool findByName(String name) {
            for (SignatureTool tool : tools) {
                if (tool.name().equals(name)) {
                    return tool;
                }
            }
            return null;
        }
    }
}
