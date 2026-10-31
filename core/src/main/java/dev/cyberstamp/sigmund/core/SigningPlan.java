package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Which keys a signing run signs with, and why it cannot sign when it cannot.
 * <p>
 * A plan is worked out when a {@link Signer} is created, from the keys each signing tool of the
 * run reports ({@link SignatureTool#signingInfo()}, one entry per key; a tool reporting none
 * counts as one key carrying only its name) and the credential types the run requests (a
 * {@code signing.profiles} entry, else {@code signing.credential-types}). When no type is
 * requested, every key signs. When types are requested, a key signs only if its
 * {@linkplain SigningInfo#credentialType() type} is one of them, and a tool left with no such key
 * does not sign — {@code signing.toolchain} names the tools that may sign, not ones that must.
 * <p>
 * A plan records a problem, rather than throwing, so that it can still be shown — what
 * {@code signer-info} prints is what signing does. Problems arise only when types are
 * requested, in this order:
 * <ol>
 * <li>each key whose type cannot be read, since the plan cannot tell whether it was meant to
 * sign;</li>
 * <li>each requested type, in requested order, that no key in the run has, with the tools in the
 * run and their key types.</li>
 * </ol>
 * {@link Signer#sign} refuses to sign while the plan has a problem, so it writes nothing. A plan
 * is immutable.
 *
 * @see Signer#plan()
 */
public final class SigningPlan {

    private static final String TYPE_UNKNOWN = "type unknown";
    private static final String DEFAULT_KEY = "default key";

    private final List<SigningInfo> keys;
    private final List<String> problems;

    private SigningPlan(List<SigningInfo> keys, List<String> problems) {
        this.keys = List.copyOf(keys);
        this.problems = List.copyOf(problems);
    }

    /**
     * Works out the plan for the given tools and requested types.
     *
     * @param tools the run's signing tools, in signing order
     * @param requestedTypes the requested credential types, empty when none are requested
     * @return the plan
     * @throws SigmundException if a tool reports a key carrying another tool's name
     */
    static SigningPlan of(List<SignatureTool> tools, List<String> requestedTypes) {
        List<SigningInfo> runKeys = runKeys(tools);
        List<SigningInfo> selected = runKeys.stream()
                .filter(key -> requestedTypes.isEmpty() || isRequested(key, requestedTypes))
                .toList();
        List<String> problems = new ArrayList<>();
        if (!requestedTypes.isEmpty()) {
            problems.addAll(unreadableTypeProblems(runKeys, requestedTypes));
            problems.addAll(missingTypeProblems(runKeys, selected, requestedTypes));
        }
        return new SigningPlan(selected, problems);
    }

    /**
     * Returns the keys that sign, in tool order and then in the order each tool reports them.
     * Each key's {@linkplain SigningInfo#toolName() tool name} is the tool that signs with it.
     * <p>
     * The keys are listed even when the plan has problems, so that they can be shown.
     *
     * @return the planned keys
     */
    public List<SigningInfo> keys() {
        return keys;
    }

    /**
     * Returns why the run cannot sign, in the order the class description gives.
     *
     * @return the problems, empty when signing can proceed
     */
    public List<String> problems() {
        return problems;
    }

    /**
     * Throws when the plan has a problem, so that no tool signs.
     *
     * @throws SigmundException with the problems joined by {@code "; "}, when there is one
     */
    void requireSignable() {
        if (!problems.isEmpty()) {
            throw new SigmundException(String.join("; ", problems));
        }
    }

    private static List<SigningInfo> runKeys(List<SignatureTool> tools) {
        List<SigningInfo> result = new ArrayList<>();
        for (SignatureTool tool : tools) {
            List<SigningInfo> reported = tool.signingInfo();
            if (reported.isEmpty()) {
                result.add(new SigningInfo(tool.name(), null, null, null, null));
            }
            for (SigningInfo key : reported) {
                if (!tool.name().equals(key.toolName())) {
                    throw new SigmundException("tool '" + tool.name() + "' reported a signing key of tool '"
                            + key.toolName() + "'");
                }
                result.add(key);
            }
        }
        return result;
    }

    private static boolean isRequested(SigningInfo key, List<String> requestedTypes) {
        return key.credentialType() != null && requestedTypes.contains(key.credentialType());
    }

    private static List<String> unreadableTypeProblems(List<SigningInfo> runKeys, List<String> requestedTypes) {
        return runKeys.stream()
                .filter(key -> key.credentialType() == null)
                .map(key -> "tool '" + key.toolName() + "': the credential type of signing key "
                        + (key.fingerprint() != null ? key.fingerprint() : DEFAULT_KEY)
                        + " cannot be read, and the run requests credential types " + requestedTypes)
                .toList();
    }

    private static List<String> missingTypeProblems(List<SigningInfo> runKeys, List<SigningInfo> selected,
            List<String> requestedTypes) {
        return requestedTypes.stream()
                .filter(type -> selected.stream().noneMatch(key -> type.equals(key.credentialType())))
                .map(type -> "no signing key for requested credential type " + type
                        + "; keys in the run: " + runKeysDisplay(runKeys))
                .toList();
    }

    private static String runKeysDisplay(List<SigningInfo> runKeys) {
        Set<String> entries = new LinkedHashSet<>();
        for (SigningInfo key : runKeys) {
            entries.add(key.toolName() + " " + (key.credentialType() != null ? key.credentialType() : TYPE_UNKNOWN));
        }
        return String.join(", ", entries);
    }
}
