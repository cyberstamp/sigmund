package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
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
 * TrustVerifier verifier = sigmund.verifier(
 *         RulePolicy.compile(config.trustPolicySpec(), config.signers()));
 * ArtifactResult result = verifier.assess(coords, artifactFile, evidenceFiles);
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
    private final VerificationConfig verificationConfig;
    private final Map<String, OpenPgpDirectory> directories;
    private final SignerIdentity expectedSigner;
    private volatile boolean fetchWarningEmitted;

    private Sigmund(List<SignatureTool> tools, List<SignatureFormat> formats,
            List<EvidenceProvider> evidenceProviders, SigningConfig signingConfig,
            VerificationConfig verificationConfig, OpenPgpDirectory directory,
            SignerIdentity expectedSigner) {
        if (tools.isEmpty()) {
            throw new SigmundException("No tools available");
        }
        this.tools = tools;
        this.formats = formats;
        this.evidenceProviders = evidenceProviders;
        this.signingConfig = signingConfig;
        this.verificationConfig = verificationConfig;
        this.directories = Map.of(directory.name(), directory);
        this.expectedSigner = expectedSigner;
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
     * Closes all tools that implement {@link AutoCloseable}, and the OpenPGP directory.
     * <p>
     * Iterates through all registered tools and attempts to close any that
     * implement {@code AutoCloseable}. Exceptions thrown by individual tools
     * are suppressed to ensure all tools have an opportunity to close. The directory's
     * HTTP client, if one was started, is released last.
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
        directories.values().forEach(OpenPgpDirectory::close);
    }

    /**
     * Creates a signer for the default {@code credential-types} (if configured): its
     * {@link SigningPlan} signs with the keys of those types, or with every key of every signing
     * tool when none are configured.
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
     * The profile maps to a list of credential types; the signer's {@link SigningPlan} signs only
     * with keys of those types. Takes precedence over the default {@code credential-types}
     * setting.
     *
     * @param profileName the profile name (e.g., {@code "classic"}, {@code "hybrid"})
     * @return a new signer for the profile's credential types
     * @throws SigmundException if the profile name is not found in the signing config, or a tool
     *         {@code signing.toolchain} names is not available or cannot sign
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

    /**
     * Creates a signer over the signing-capable tools, narrowed and ordered by
     * {@code signing.toolchain} when it is set, for the given requested types. Which keys sign is
     * left to the signer's {@link SigningPlan}.
     */
    private Signer signerForCredentialTypes(List<String> credentialTypes) {
        List<SignatureTool> candidates = tools.stream().filter(SignatureTool::canSign).toList();
        return new Signer(configuredSigningTools(candidates), credentialTypes, signerBindingCheck());
    }

    /**
     * Returns the check that every signature proves the signer {@code signing.signer} asserts,
     * or {@code null} when no signer is asserted.
     * <p>
     * Signing asks a directory about a key's addresses only when
     * {@code verification.resolve-signers} allows it, as verification does, and verifies a fresh
     * signature with the tool that produced it, then the other tools of its format.
     */
    private SignerBindingCheck signerBindingCheck() {
        if (expectedSigner == null) {
            return null;
        }
        return new SignerBindingCheck(expectedSigner, directories, verificationConfig.resolveSigners(), tools);
    }

    /**
     * Filters signing tool candidates to only those listed in {@link SigningConfig#toolchain()}.
     * <p>
     * When the signing toolchain is empty, returns the candidates unchanged.
     * When tools are configured, each must be present in the candidates list; if a
     * configured tool is missing, an exception is thrown with a diagnostic message
     * (not available or not signing-capable). A configured tool with no key of a requested type
     * does not sign; the {@link SigningPlan} decides which keys sign.
     * <p>
     * The result preserves the iteration order of {@link SigningConfig#toolchain()}, so
     * the signing order matches the user's YAML configuration.
     *
     * @param candidates signing-capable tools
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
     * from the candidate list: not registered, or not signing-capable.
     */
    private String diagnoseSigningFailure(String toolName) {
        return tool(toolName) == null ? "not available" : "not signing-capable";
    }

    /**
     * Creates a trust verifier using the given policy.
     * <p>
     * The {@link VerificationConfig} set at build time is used for key fetching.
     *
     * @param policy the trust policy to apply
     * @return a new trust verifier
     */
    public TrustVerifier verifier(TrustPolicy policy) {
        warnIfNoFetchCapableImporter();
        return new TrustVerifier(policy, evidenceProviders, new ClaimIdentityResolver(policy,
                directories, verificationConfig.resolveSigners()));
    }

    /**
     * Returns the identities directories vouch for a key: each address a directory among the
     * given issuers has verified for it, as an email identity from that directory.
     * <p>
     * This is the question verification asks for a signer named by address, asked outside
     * verification — by an update deciding whether a new key belongs to a signer the policy
     * already names. Only issuers that are known directories are asked; any other is skipped.
     * The directories are asked over the network whatever {@code verification.resolve-signers}
     * says, so a caller honoring it does not call this when it is off.
     *
     * @param key the key whose addresses to ask for
     * @param issuers issuer names, in any form {@link IssuerKind#canonicalName(String)} accepts
     * @return the identities, empty when no directory among the issuers serves an address for it
     * @throws IOException if a directory cannot be reached
     */
    public List<IdentityCredential> directoryIdentities(KeyCredential key, Collection<String> issuers)
            throws IOException {
        List<String> names = issuers.stream().map(IssuerKind::canonicalName).distinct().toList();
        return ClaimIdentityResolver.directoryIdentities(directories, names, key.fingerprint());
    }

    private void warnIfNoFetchCapableImporter() {
        if (fetchWarningEmitted || !verificationConfig.resolveSigners()) {
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
     * {@link VerificationConfig}. Explicit {@link #addTool(SignatureTool)} calls take precedence.
     * {@link #config(SigmundConfig)} applies the full config including signing, tool, and
     * verification settings. {@link #verificationConfig(VerificationConfig)} sets key fetching config.
     * {@link #toolsConfig(ToolsConfig)} sets per-tool configuration overrides.
     */
    public static class Builder {

        private final List<SignatureTool> tools = new ArrayList<>(2);
        private final List<EvidenceProvider> extraProviders = new ArrayList<>();
        private ToolsConfig toolsConfig = ToolsConfig.EMPTY;
        private VerificationConfig verificationConfig = VerificationConfig.DEFAULT;
        private OpenPgpDirectory directory;
        private SigningConfig signingConfig;
        private SignerIdentity expectedSigner;
        private List<SignatureToolFactory> factoryOverride;
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
         * Replaces the directory asked for verified addresses, such as with a local stand-in.
         *
         * @param directory the directory
         * @return this builder
         */
        Builder openPgpDirectory(OpenPgpDirectory directory) {
            this.directory = directory;
            return this;
        }

        /**
         * Sets key fetching and keyserver configuration, fixed at build time.
         * All {@link TrustVerifier} instances created from this {@link Sigmund} share it.
         *
         * @param dc the verification configuration
         * @return this builder
         */
        public Builder verificationConfig(VerificationConfig dc) {
            this.verificationConfig = dc != null ? dc : VerificationConfig.DEFAULT;
            return this;
        }

        /**
         * Applies the full configuration.
         * <p>
         * Overrides any prior {@code toolsConfig()} or {@code verificationConfig()} call.
         * Explicit {@code addTool()} calls take precedence over initialized tools.
         *
         * @param config the unified configuration
         * @return this builder
         */
        public Builder config(SigmundConfig config) {
            this.toolsConfig = config.toolsConfig();
            this.verificationConfig = config.verificationConfig();
            this.signingConfig = config.signingConfig();
            this.expectedSigner = expectedSignerOf(config);
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
         * configured (e.g., {@code "signing-fingerprint"}, {@code "home"}).
         * <p>
         * The factory receives the signer {@code signing.signer} asserts only when
         * {@link #config(SigmundConfig)} was called before this method; otherwise it receives
         * {@code null} and cannot refuse early (Sigstore then accepts any OIDC token). The check
         * that every signature proves the asserted signer runs after signing regardless, as long
         * as {@code config} is called before {@link #build()}.
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

        private static SignerIdentity expectedSignerOf(SigmundConfig config) {
            String name = config.signingConfig() == null ? null : config.signingConfig().signer();
            if (name == null) {
                return null;
            }
            return config.signers().resolve(name)
                    .withIssuersResolved(config.trustPolicySpec().issuers());
        }

        private SignatureTool createFromFactory(String toolName, boolean signing,
                Map<String, String> configured) {
            Map<String, String> settings = withSharedDefaults(toolName, configured);
            for (SignatureToolFactory factory : allFactories()) {
                if (factory.toolName().equals(toolName)) {
                    if (signing && factory instanceof BcToolFactory bcFactory
                            && bcPassphraseProvider != null) {
                        return bcFactory.createSigning(settings, expectedSigner, bcPassphraseProvider);
                    }
                    return signing
                            ? factory.createSigning(settings, expectedSigner)
                            : factory.createVerifyOnly(settings);
                }
            }
            throw new SigmundException(unknownToolMessage(toolName));
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
         * First initializes tools from registered factories based on {@link VerificationConfig}
         * (explicit {@link #addTool} calls take precedence — already-added tools are
         * skipped), then enforces exclusive signer constraints (see
         * {@link SignatureToolFactory#isDefaultExclusiveSigner()}). When no signing
         * tools are explicitly configured and a factory claims exclusivity, all
         * other signing-capable tools are removed and the exclusive tool becomes
         * the sole signer. Verify-only tools are kept.
         *
         * @return the configured Sigmund instance
         * @throws PolicyConfigException if the configuration names a tool no factory builds, or a
         *         setting its tool does not accept
         * @throws SigmundException if no tools are available, or if multiple tools
         *         claim exclusive signing
         */
        public Sigmund build() {
            try {
                checkToolConfiguration();
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
                        List.copyOf(providers), signingConfig, verificationConfig,
                        directory != null ? directory : KeysOpenPgpOrgDirectory.standard(),
                        expectedSigner);
            } catch (RuntimeException e) {
                // Clean up any AutoCloseable tools before propagating the exception
                closeTools();
                throw e;
            }
        }

        /**
         * Checks the tool names and settings the configuration writes against the factories,
         * before any tool is built.
         * <p>
         * Which tools exist, and which settings each accepts, is known only to the factories on
         * the classpath, so the parser leaves these names to be checked here. A misspelled tool or
         * setting would otherwise configure nothing and leave the tool on its defaults. A
         * toolchain may also name a tool added with {@link #addTool(SignatureTool)}.
         *
         * @throws PolicyConfigException naming the unknown tool or setting and the nearest known one
         */
        void checkToolConfiguration() {
            for (String toolName : toolsConfig.toolNames()) {
                SignatureToolFactory factory = factoryFor("tools", toolName);
                ToolConfig config = toolsConfig.get(toolName);
                Map<String, String> settings = config.settings();
                checkSettings(toolName, settings.keySet(), factory.acceptedSettings());
                checkListSettings(toolName, config, factory.listSettings());
                factory.checkSettingValues(settings);
            }
            if (verificationConfig.toolchain() != null) {
                checkToolchain("verification.toolchain", verificationConfig.toolchain());
            }
            if (signingConfig != null) {
                checkToolchain("signing.toolchain", signingConfig.toolchain());
            }
        }

        private static void checkListSettings(String toolName, ToolConfig config, Set<String> takingLists) {
            for (String key : config.lists()) {
                if (!takingLists.contains(key)) {
                    throw new PolicyConfigException(
                            "tools." + toolName + "." + key + " must be a single value, not a list");
                }
            }
            for (String key : takingLists) {
                String value = config.settings().get(key);
                if (value != null && !config.lists().contains(key) && value.contains(ToolSetting.LIST_SEPARATOR)) {
                    throw new PolicyConfigException("tools." + toolName + "." + key + ": '" + value
                            + "' holds more than one value; write them as a list");
                }
            }
        }

        private void checkToolchain(String location, List<String> toolchain) {
            for (String toolName : toolchain) {
                if (findByName(toolName) == null) {
                    factoryFor(location, toolName);
                }
            }
        }

        private SignatureToolFactory factoryFor(String location, String toolName) {
            for (SignatureToolFactory factory : allFactories()) {
                if (factory.toolName().equals(toolName)) {
                    return factory;
                }
            }
            throw new PolicyConfigException(location + ": " + unknownToolMessage(toolName));
        }

        private String unknownToolMessage(String toolName) {
            List<String> names = allFactories().stream().map(SignatureToolFactory::toolName).toList();
            String suggestion = NearestName.among(toolName, names);
            return "unknown tool '" + toolName + "'"
                    + (suggestion == null ? "" : " — did you mean '" + suggestion + "'?")
                    + " (tools available: " + String.join(", ", names) + ")";
        }

        private static void checkSettings(String toolName, Set<String> written, Set<String> accepted) {
            List<String> known = accepted.stream().sorted().toList();
            for (String setting : written) {
                if (!accepted.contains(setting)) {
                    String suggestion = NearestName.among(setting, known);
                    throw new PolicyConfigException("tools." + toolName + ": unknown setting '" + setting + "'"
                            + (suggestion == null
                                    ? "; expected one of " + String.join(", ", known)
                                    : " — did you mean '" + suggestion + "'?"));
                }
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

        /**
         * Replaces the factories tools are built from, so a test can observe what they receive.
         *
         * @param factories the factories to use instead of the built-in and discovered ones
         * @return this builder
         */
        Builder factories(List<SignatureToolFactory> factories) {
            this.factoryOverride = List.copyOf(factories);
            return this;
        }

        private List<SignatureToolFactory> allFactories() {
            return factoryOverride != null ? factoryOverride : ALL_FACTORIES;
        }

        /**
         * Initializes tools from registered factories using the verification toolchain.
         * <p>
         * Reads the toolchain from {@link VerificationConfig#effectiveToolchain()} and
         * per-tool settings from {@link ToolsConfig}. Explicitly added tools are skipped.
         */
        private void initializeTools() {
            List<String> priority = verificationConfig.effectiveToolchain();
            for (String toolName : priority) {
                if (findByName(toolName) != null) {
                    continue;
                }
                initializeTool(toolName);
            }
            if (verificationConfig.toolchain() == null) {
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
         * from {@link ToolsConfig} with verification settings from {@link VerificationConfig}.
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
                Map<String, String> settings = withSharedDefaults(toolName, resolveToolSettings(toolName));
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
         * Adds the defaults one tool takes from another's settings: bc reads public keys from the
         * GnuPG home {@code tools.gpg.home} names, unless {@code tools.bc.gnupg-home} is set.
         *
         * @param toolName the tool being built
         * @param settings its own settings
         * @return the settings with the shared defaults added, a new map
         */
        private Map<String, String> withSharedDefaults(String toolName, Map<String, String> settings) {
            Map<String, String> merged = new HashMap<>(settings);
            if (BcToolFactory.NAME.equals(toolName)) {
                ToolConfig gpg = toolsConfig.get(GpgToolFactory.NAME);
                BcToolFactory.defaultGnupgHome(merged, gpg == null ? null : GpgToolFactory.home(gpg.settings()));
            }
            return Map.copyOf(merged);
        }

        /**
         * Returns whether the given factory supports any OpenPGP credential type.
         *
         * @param factory the factory to check
         * @return {@code true} if the factory supports {@code pgp4} or {@code pgp6}
         */
        private static boolean supportsOpenPgp(SignatureToolFactory factory) {
            Set<String> types = factory.supportedCredentialTypes();
            return types.contains(Credential.TYPE_PGP4)
                    || types.contains(Credential.TYPE_PGP6);
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
         * Injects verification-level fetch settings into a tool's settings map.
         * These settings are read by tool factories to configure key fetching behavior.
         *
         * @param toolSettings the base tool settings (may be mutated)
         * @return an immutable copy of the merged settings
         */
        private Map<String, String> injectFetchSettings(Map<String, String> toolSettings) {
            var merged = new HashMap<>(toolSettings);
            merged.put(FetchSetting.RESOLVE_SIGNERS.key(), String.valueOf(verificationConfig.resolveSigners()));
            merged.put(FetchSetting.IMPORT_TO_KEYRING.key(), String.valueOf(verificationConfig.importToKeyring()));
            merged.put(FetchSetting.KEYSERVERS.key(), String.join(",", verificationConfig.keyservers()));
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
