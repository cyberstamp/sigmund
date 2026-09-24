package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * The central facade for Sigmund — tool registry, signature verification, and session creation.
 *
 * <h2>Usage from config file</h2>
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
 * <h2>Programmatic construction</h2>
 *
 * <pre>{@code
 * Sigmund sigmund = Sigmund.builder()
 *         .addTool(new GpgRunner("mykey"))
 *         .addTool(new SqRunner("sq", sqHome, fingerprint))
 *         .build();
 * }</pre>
 *
 * <h2>Verify-only</h2>
 *
 * <pre>{@code
 * Sigmund sigmund = Sigmund.builder().build();
 * SignatureVerificationReport report = sigmund.verify(artifactFile, signatureFile);
 * }</pre>
 *
 * @see Signer
 * @see TrustVerifier
 */
public class Sigmund implements AutoCloseable {

    private final List<SignatureTool> tools;
    private final List<EvidenceProvider> evidenceProviders;
    private final SigningConfig signingConfig;
    private final List<SignatureFormat> formats;
    private final DiscoveryConfig discoveryConfig;
    private volatile boolean fetchWarningEmitted;

    private Sigmund(List<SignatureTool> tools, List<SignatureFormat> formats,
            List<EvidenceProvider> evidenceProviders, SigningConfig signingConfig,
            DiscoveryConfig discoveryConfig) {
        if (tools.isEmpty()) {
            throw new SigmundException("No tools available");
        }
        this.tools = tools;
        this.formats = formats;
        this.evidenceProviders = evidenceProviders;
        this.signingConfig = signingConfig;
        this.discoveryConfig = discoveryConfig;
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
     * Closes all tools that implement {@link AutoCloseable}.
     * <p>
     * Iterates through all registered tools and attempts to close any that
     * implement {@code AutoCloseable}. Exceptions thrown by individual tools
     * are suppressed to ensure all tools have an opportunity to close.
     * <p>
     * This method is idempotent — calling it multiple times has the same
     * effect as calling it once.
     */
    @Override
    public void close() {
        for (SignatureTool tool : tools) {
            if (tool instanceof AutoCloseable ac) {
                try {
                    ac.close();
                } catch (Exception ignored) {
                    // Suppress exceptions to allow all tools to close
                }
            }
        }
    }

    /**
     * Creates a signer using the default {@code credential-types} filter (if configured),
     * or all available signing tools when no filter is set.
     *
     * @return a new signer
     */
    public Signer signer() {
        List<String> credentialTypes = signingConfig != null ? signingConfig.credentialTypes() : List.of();
        return signerForCredentialTypes(credentialTypes);
    }

    /**
     * Creates a signer using a named profile from the signing configuration.
     * <p>
     * The profile maps to a list of credential types; only tools whose
     * {@link SignatureTool#supportedCredentialTypes()} intersects with the
     * profile's credential types are included. Takes precedence over the
     * default {@code credential-types} setting.
     *
     * @param profileName the profile name (e.g., {@code "classic"}, {@code "hybrid"})
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
        return signerForCredentialTypes(credentialTypes);
    }

    private Signer signerForCredentialTypes(List<String> credentialTypes) {
        List<SignatureTool> candidates = tools.stream().filter(SignatureTool::canSign).toList();
        if (!credentialTypes.isEmpty()) {
            candidates = candidates.stream()
                    .filter(t -> t.supportedCredentialTypes().stream()
                            .anyMatch(credentialTypes::contains))
                    .toList();
        }
        return new Signer(configuredSigningTools(candidates));
    }

    /**
     * Filters signing tool candidates to only those listed in {@link SigningConfig#toolchain()}.
     * <p>
     * When the signing toolchain is empty, returns the candidates unchanged.
     * When tools are configured, each must be present in the candidates list; if a
     * configured tool is missing, an exception is thrown with a diagnostic message
     * (not available, not signing-capable, or credential type mismatch).
     * <p>
     * The result preserves the iteration order of {@link SigningConfig#toolchain()}, so
     * the signing order matches the user's YAML configuration.
     *
     * @param candidates signing-capable tools, possibly pre-filtered by profile credential types
     * @return the configured subset of candidates
     * @throws SigmundException if a configured tool is not in the candidates list
     */
    private List<SignatureTool> configuredSigningTools(List<SignatureTool> candidates) {
        if (signingConfig == null || signingConfig.toolchain().isEmpty()) {
            return candidates;
        }
        Map<String, SignatureTool> candidatesByName = new HashMap<>();
        for (SignatureTool t : candidates) {
            candidatesByName.put(t.name(), t);
        }
        List<SignatureTool> result = new ArrayList<>();
        for (String toolName : signingConfig.toolchain()) {
            SignatureTool t = candidatesByName.get(toolName);
            if (t != null) {
                result.add(t);
            } else {
                throw new SigmundException(
                        "Configured signing tool '" + toolName + "': "
                                + diagnoseSigningFailure(toolName));
            }
        }
        return result;
    }

    /**
     * Returns a human-readable reason why a configured signing tool is absent
     * from the candidate list: not registered, not signing-capable, or filtered
     * out by profile credential types.
     */
    private String diagnoseSigningFailure(String toolName) {
        SignatureTool registered = tool(toolName);
        if (registered == null) {
            return "not available";
        }
        if (!registered.canSign()) {
            return "not signing-capable";
        }
        return "does not match the requested credential types";
    }

    /**
     * Creates a trust verifier using the given policy.
     * <p>
     * The {@link DiscoveryConfig} set at build time is used for key fetching.
     *
     * @param policy the trust policy to apply
     * @return a new trust verifier
     */
    public TrustVerifier verifier(TrustPolicy policy) {
        warnIfNoFetchCapableImporter();
        return new TrustVerifier(policy, evidenceProviders);
    }

    private void warnIfNoFetchCapableImporter() {
        if (fetchWarningEmitted || !discoveryConfig.resolveSigners()) {
            return;
        }
        for (SignatureTool tool : tools) {
            if (tool instanceof KeyImporter ki && ki.canFetchKeys()) {
                return;
            }
        }
        fetchWarningEmitted = true;
        System.getLogger(Sigmund.class.getName())
                .log(System.Logger.Level.WARNING,
                        "resolve-signers is enabled but no tool can fetch keys; "
                                + "set import-to-keyring: true or add bc to toolchain");
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

    /**
     * Returns the set of signature file extensions produced by all configured formats.
     * <p>
     * The returned set preserves iteration order (format registration order) and
     * is immutable. For example, if OpenPGP ({@code .asc}) and Sigstore
     * ({@code .sigstore.json}) formats are registered, the set contains both extensions.
     *
     * @return an unmodifiable set of file extensions including leading dots
     */
    public Set<String> signatureFileExtensions() {
        Set<String> extensions = new LinkedHashSet<>();
        for (SignatureFormat format : formats) {
            extensions.add(format.fileExtension());
        }
        return Set.copyOf(extensions);
    }

    /**
     * Inspects a signer identity across available tools and their configured sources.
     *
     * @param credential the identity to look up
     * @param toolName optional tool name to restrict inspection to a single tool;
     *        null to use all capable tools
     * @return the aggregated inspection report
     */
    public SignerInspectionReport inspectSigner(Credential credential, String toolName) {
        List<SignerSourceResult> allResults = new ArrayList<>();

        if (toolName != null) {
            SignerInspection inspector = findTool(SignerInspection.class, toolName);
            if (inspector != null && inspector.canInspect(credential)) {
                allResults.addAll(inspector.inspect(credential));
            }
        } else {
            for (SignatureTool tool : tools) {
                if (tool instanceof SignerInspection si && si.canInspect(credential)) {
                    allResults.addAll(si.inspect(credential));
                }
            }
        }

        return new SignerInspectionReport(credential, allResults);
    }

    private FileSignatureReport verifySingleFile(Path artifactFile, Path signatureFile) {
        Evidence evidence = Evidence.read(signatureFile, Evidence.SOURCE_SIDECAR);
        SignatureFormat format = findFormat(evidence);
        if (format == null) {
            return new FileSignatureReport(signatureFile, "unknown", List.of());
        }
        List<Claim> claims = format.parse(evidence);
        List<VerifyResult> results = new ArrayList<>();
        for (Claim claim : claims) {
            VerifyResult result = verifyClaim(artifactFile, claim);
            if (result != null) {
                results.add(result);
            }
        }
        return new FileSignatureReport(signatureFile, format.name(), results);
    }

    private SignatureFormat findFormat(Evidence evidence) {
        for (SignatureFormat format : formats) {
            if (format.canHandle(evidence)) {
                return format;
            }
        }
        return null;
    }

    /**
     * Verifies a single claim against the artifact file.
     * <p>
     * Tries each tool in priority order. Only {@link ClaimOutcome#VERIFIED} stops
     * iteration immediately; a claim no tool supports falls through to the next tool, and
     * the most conclusive answer seen so far is kept
     * ({@link VerifyResult#isMoreConclusiveThan}). This
     * allows tools with different key stores (BC ephemeral cache, GPG
     * {@code pubring.kbx}, Sequoia cert store) to complement each other.
     *
     * @return the best result, or {@code null} if all tools returned {@code SKIPPED}
     */
    private VerifyResult verifyClaim(Path artifactFile, Claim claim) {
        VerifyResult best = null;
        for (SignatureTool tool : tools) {
            if (!tool.canVerify(claim)) {
                continue;
            }
            VerifyResult result = tool.verify(artifactFile, claim);
            if (result.isVerified()) {
                return result;
            }
            if (result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)) {
                continue;
            }
            if (result.isMoreConclusiveThan(best)) {
                best = result;
            }
        }
        return best;
    }

    /**
     * Builder for constructing a {@link Sigmund} instance.
     * <p>
     * {@link #build()} always initializes tools from registered factories based on the
     * {@link DiscoveryConfig}. Explicit {@link #addTool(SignatureTool)} calls take precedence.
     * {@link #config(SigmundConfig)} applies the full config including signing, tool, and
     * discovery settings. {@link #discoveryConfig(DiscoveryConfig)} sets key fetching config.
     * {@link #toolsConfig(ToolsConfig)} sets per-tool configuration overrides.
     */
    public static class Builder {

        private final List<SignatureTool> tools = new ArrayList<>(2);
        private final List<EvidenceProvider> extraProviders = new ArrayList<>();
        private ToolsConfig toolsConfig = ToolsConfig.EMPTY;
        private DiscoveryConfig discoveryConfig = DiscoveryConfig.DEFAULT;
        private SigningConfig signingConfig;
        private PassphraseProvider bcPassphraseProvider;

        /**
         * Sets per-tool configuration overrides from the top-level {@code tools} section.
         *
         * @param tc the tool registry
         * @return this builder
         */
        public Builder toolsConfig(ToolsConfig tc) {
            this.toolsConfig = tc != null ? tc : ToolsConfig.EMPTY;
            return this;
        }

        /**
         * Sets key fetching and keyserver configuration, fixed at build time.
         * All {@link TrustVerifier} instances created from this {@link Sigmund} share it.
         *
         * @param dc the discovery configuration
         * @return this builder
         */
        public Builder discoveryConfig(DiscoveryConfig dc) {
            this.discoveryConfig = dc != null ? dc : DiscoveryConfig.DEFAULT;
            return this;
        }

        /**
         * Applies the full configuration.
         * <p>
         * Overrides any prior {@code toolsConfig()} or {@code discoveryConfig()} call.
         * Explicit {@code addTool()} calls take precedence over initialized tools.
         *
         * @param config the unified configuration
         * @return this builder
         */
        public Builder config(SigmundConfig config) {
            this.toolsConfig = config.toolsConfig();
            this.discoveryConfig = config.discoveryConfig();
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

        private SignatureTool createFromFactory(String toolName, boolean signing, Map<String, String> settings) {
            for (SignatureToolFactory factory : allFactories()) {
                if (factory.toolName().equals(toolName)) {
                    if (signing && factory instanceof BcToolFactory bcFactory
                            && bcPassphraseProvider != null) {
                        return bcFactory.createSigning(null, settings, bcPassphraseProvider);
                    }
                    return signing
                            ? factory.createSigning(null, settings)
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
         * First initializes tools from registered factories based on {@link DiscoveryConfig}
         * (explicit {@link #addTool} calls take precedence — already-added tools are
         * skipped), then enforces exclusive signer constraints (see
         * {@link SignatureToolFactory#isDefaultExclusiveSigner()}). When no signing
         * tools are explicitly configured and a factory claims exclusivity, all
         * other signing-capable tools are removed and the exclusive tool becomes
         * the sole signer. Verify-only tools are kept.
         *
         * @return the configured Sigmund instance
         * @throws SigmundException if no tools are available, or if multiple tools
         *         claim exclusive signing
         */
        public Sigmund build() {
            try {
                initializeTools();
                enforceExclusiveSigners();

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
                    providers.add(new SignatureEvidenceAdapter(format, group));
                }
                for (EvidenceProvider ep : extraProviders) {
                    if (ep.isAvailable()) {
                        providers.add(ep);
                    }
                }

                return new Sigmund(List.copyOf(tools), List.copyOf(formats),
                        List.copyOf(providers), signingConfig, discoveryConfig);
            } catch (RuntimeException e) {
                // Clean up any AutoCloseable tools before propagating the exception
                closeTools();
                throw e;
            }
        }

        /**
         * Closes all tools that implement {@link AutoCloseable}.
         * <p>
         * Used during builder cleanup when construction fails after tools
         * have been initialized. Exceptions from individual tools are suppressed.
         */
        private void closeTools() {
            for (SignatureTool tool : tools) {
                if (tool instanceof AutoCloseable ac) {
                    try {
                        ac.close();
                    } catch (Exception ignored) {
                        // Suppress exceptions during cleanup
                    }
                }
            }
        }

        /**
         * Polls registered factories for default exclusive signer claims when no
         * signing tools are explicitly configured in {@code sigmund.yaml}.
         * <p>
         * This method is a no-op when {@link SigningConfig#toolchain()} is non-empty —
         * the user has explicitly chosen their signing tools, so factory-level
         * exclusivity does not apply. In that case, the env var still participates
         * as a key provider through {@link BcToolFactory}'s key priority, but does
         * not alter the tool selection.
         * <p>
         * When no signing tools are configured and exactly one factory's
         * {@link SignatureToolFactory#isDefaultExclusiveSigner()} returns {@code true}:
         * <ul>
         * <li>All other signing-capable tools are removed. Verify-only tools
         * are kept for signature verification.</li>
         * <li>If the exclusive tool is not yet present as a signing-capable
         * tool, any verify-only instance is replaced with a signing-capable
         * one.</li>
         * <li>The {@link SigningConfig} is cleared so that residual config-file
         * tool restrictions do not filter out the exclusive tool.</li>
         * </ul>
         *
         * @throws SigmundException if multiple factories claim default exclusive signing
         */
        private void enforceExclusiveSigners() {
            enforceExclusiveSigners(allFactories());
        }

        /**
         * Polls the given factories for default exclusive signer claims when no
         * signing tools are explicitly configured in {@code sigmund.yaml}.
         * <p>
         * Package-private overload that accepts a factory list, allowing tests
         * to inject mock factories that claim exclusivity without requiring the
         * {@code SIGMUND_BC_SIGNING_KEY} environment variable to be set.
         *
         * @param factories the factories to poll for
         *        {@link SignatureToolFactory#isDefaultExclusiveSigner()} claims
         * @throws SigmundException if multiple factories claim default exclusive signing
         * @see #enforceExclusiveSigners()
         */
        void enforceExclusiveSigners(List<SignatureToolFactory> factories) {
            if (signingConfig != null && !signingConfig.toolchain().isEmpty()) {
                return;
            }
            SignatureToolFactory exclusive = null;
            for (SignatureToolFactory factory : factories) {
                if (factory.isDefaultExclusiveSigner()) {
                    if (exclusive != null) {
                        throw new SigmundException(
                                "Multiple signing tools claim exclusive signing: "
                                        + exclusive.toolName() + ", " + factory.toolName());
                    }
                    exclusive = factory;
                }
            }
            if (exclusive == null) {
                return;
            }
            String name = exclusive.toolName();
            tools.removeIf(t -> t.canSign() && !name.equals(t.name()));
            SignatureTool existing = findByName(name);
            if (existing == null || !existing.canSign()) {
                if (existing != null) {
                    tools.remove(existing);
                }
                Map<String, String> settings = resolveToolSettings(name);
                addSigningTool(name, settings);
            }
            signingConfig = null;
        }

        private static final List<SignatureToolFactory> BUILTIN_FACTORIES = List.of(
                new BcToolFactory(), new GpgToolFactory(), new SqToolFactory());

        /** Built-in factories followed by ServiceLoader-discovered ones, resolved once. */
        private static final List<SignatureToolFactory> ALL_FACTORIES = loadAllFactories();

        /**
         * Returns all factories: built-in factories followed by ServiceLoader-discovered ones.
         *
         * <p>
         * Discovered factories whose {@link SignatureToolFactory#supportedCredentialTypes()}
         * overlap with a built-in factory's types are included. When such overlap exists and
         * no toolchain is explicitly configured in {@code sigmund.yaml}, the caller must
         * detect and reject the ambiguity.
         *
         * @return the combined list of factories
         */
        private static List<SignatureToolFactory> loadAllFactories() {
            List<SignatureToolFactory> all = new ArrayList<>(BUILTIN_FACTORIES);
            ServiceLoader.load(SignatureToolFactory.class).forEach(all::add);
            return List.copyOf(all);
        }

        private static List<SignatureToolFactory> allFactories() {
            return ALL_FACTORIES;
        }

        /**
         * Initializes tools from registered factories using the discovery toolchain.
         * <p>
         * Reads the toolchain from {@link DiscoveryConfig#effectiveToolchain()} and
         * per-tool settings from {@link ToolsConfig}. Explicitly added tools are skipped.
         */
        private void initializeTools() {
            List<String> priority = discoveryConfig.effectiveToolchain();
            for (String toolName : priority) {
                if (findByName(toolName) != null) {
                    continue;
                }
                initializeTool(toolName);
            }
            if (discoveryConfig.toolchain() == null) {
                for (SignatureToolFactory factory : allFactories()) {
                    if (findByName(factory.toolName()) == null
                            && !priority.contains(factory.toolName())) {
                        initializeTool(factory.toolName());
                    }
                }
            }
        }

        /**
         * Initializes a single tool from its factory, merging per-tool settings
         * from {@link ToolsConfig} with discovery settings from {@link DiscoveryConfig}.
         * <p>
         * OpenPGP-specific fetch settings ({@code resolve-signers}, {@code import-to-keyring},
         * {@code keyservers}) are only injected for factories whose
         * {@link SignatureToolFactory#supportedCredentialTypes()} includes OpenPGP types.
         *
         * @param toolName the name of the tool to initialize
         */
        private void initializeTool(String toolName) {
            for (SignatureToolFactory factory : allFactories()) {
                if (!factory.toolName().equals(toolName)) {
                    continue;
                }
                Map<String, String> settings = resolveToolSettings(toolName);
                if (supportsOpenPgp(factory)) {
                    settings = injectFetchSettings(settings);
                } else {
                    settings = Map.copyOf(settings);
                }
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
                            "Unknown tool '" + toolName + "' in toolchain");
        }

        /**
         * Returns whether the given factory supports any OpenPGP credential type.
         *
         * @param factory the factory to check
         * @return {@code true} if the factory supports {@code openpgp4} or {@code openpgp6}
         */
        private static boolean supportsOpenPgp(SignatureToolFactory factory) {
            Set<String> types = factory.supportedCredentialTypes();
            return types.contains(Credential.TYPE_OPENPGP_V4)
                    || types.contains(Credential.TYPE_OPENPGP_V6);
        }

        /**
         * Resolves per-tool settings from the {@link ToolsConfig} registry.
         * Returns the tool's settings map if a {@link ToolConfig} exists for the
         * given name, or an empty map otherwise.
         *
         * @param toolName the tool name to look up
         * @return the tool's settings, never {@code null}
         */
        private Map<String, String> resolveToolSettings(String toolName) {
            ToolConfig tc = toolsConfig.get(toolName);
            return tc != null ? new HashMap<>(tc.settings()) : new HashMap<>();
        }

        /**
         * Injects discovery-level fetch settings into a tool's settings map.
         * These settings are read by tool factories to configure key fetching behavior.
         *
         * @param toolSettings the base tool settings (may be mutated)
         * @return an immutable copy of the merged settings
         */
        private Map<String, String> injectFetchSettings(Map<String, String> toolSettings) {
            var merged = new HashMap<>(toolSettings);
            merged.put("resolve-signers", String.valueOf(discoveryConfig.resolveSigners()));
            merged.put("import-to-keyring", String.valueOf(discoveryConfig.importToKeyring()));
            merged.put("keyservers", String.join(",", discoveryConfig.keyservers()));
            return Map.copyOf(merged);
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
