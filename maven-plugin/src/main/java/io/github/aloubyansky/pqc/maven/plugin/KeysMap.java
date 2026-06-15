package io.github.aloubyansky.pqc.maven.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps Maven artifact coordinates to expected signature keys.
 * <p>
 * Parsed from a {@code keys.map} file with the format:
 *
 * <pre>
 * # Group-only (matches any artifact in the group)
 * com.example = 0xABCD1234ABCD1234
 *
 * # Group + artifact
 * com.example:lib = 0xABCD1234ABCD1234, pqc:FINGERPRINT
 *
 * # Wildcard group (matches group and all subgroups)
 * com.example.* = any
 *
 * # Wildcard artifact
 * com.example:* = 0xABCD1234ABCD1234
 *
 * # No signature expected
 * com.internal:* = noSig
 *
 * # PQC certificate file (supports ${property} interpolation)
 * org.example:secure = pqc-cert:${project.basedir}/certs/signer.cert
 * </pre>
 *
 * Entries are matched in order; the first match wins.
 *
 * @see VerifyDependenciesMojo
 */
public class KeysMap {

    private static final Pattern PROPERTY_PATTERN = Pattern.compile("\\$\\{([^}]+)}");

    private final List<Entry> entries;

    private KeysMap(List<Entry> entries) {
        this.entries = Collections.unmodifiableList(entries);
    }

    public List<Entry> entries() {
        return entries;
    }

    /**
     * Finds the first entry matching the given coordinates.
     *
     * @return the matching entry, or null if no entry matches
     */
    public Entry findMatch(String groupId, String artifactId) {
        for (Entry entry : entries) {
            if (matchesEntry(entry, groupId, artifactId)) {
                return entry;
            }
        }
        return null;
    }

    private static boolean matchesEntry(Entry entry, String groupId, String artifactId) {
        if (!matchesGroup(entry.groupPattern(), groupId)) {
            return false;
        }
        if (entry.artifactPattern() == null) {
            return true;
        }
        return matchesSegment(entry.artifactPattern(), artifactId);
    }

    private static boolean matchesGroup(String pattern, String groupId) {
        if (pattern.endsWith(".*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return groupId.equals(prefix) || groupId.startsWith(prefix + ".");
        }
        return pattern.equals(groupId);
    }

    private static boolean matchesSegment(String pattern, String value) {
        if ("*".equals(pattern)) {
            return true;
        }
        return pattern.equals(value);
    }

    /**
     * Parses a keys.map file using {@link System#getProperty} for property interpolation.
     */
    public static KeysMap parse(Path file) throws IOException {
        return parse(file, System::getProperty);
    }

    /**
     * Parses a keys.map file with a custom property resolver.
     *
     * @param file the keys.map file to parse
     * @param propertyResolver resolves {@code ${name}} placeholders; returns null for unknown properties
     */
    public static KeysMap parse(Path file, Function<String, String> propertyResolver) throws IOException {
        List<String> lines = Files.readAllLines(file);
        List<Entry> entries = new ArrayList<>();
        for (String line : lines) {
            line = line.strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int eqPos = line.indexOf('=');
            if (eqPos < 0) {
                continue;
            }
            String pattern = line.substring(0, eqPos).strip();
            String specsStr = line.substring(eqPos + 1).strip();

            String groupPattern;
            String artifactPattern;
            int colonPos = pattern.indexOf(':');
            if (colonPos >= 0) {
                groupPattern = pattern.substring(0, colonPos);
                artifactPattern = pattern.substring(colonPos + 1);
            } else {
                groupPattern = pattern;
                artifactPattern = null;
            }

            List<KeySpec> keySpecs = parseKeySpecs(specsStr, propertyResolver);
            entries.add(new Entry(groupPattern, artifactPattern, keySpecs));
        }
        return new KeysMap(entries);
    }

    private static List<KeySpec> parseKeySpecs(String specsStr, Function<String, String> propertyResolver) {
        List<KeySpec> specs = new ArrayList<>();
        for (String raw : specsStr.split(",")) {
            String spec = raw.strip();
            if (spec.isEmpty()) {
                continue;
            }
            if (spec.equalsIgnoreCase("any")) {
                specs.add(new KeySpec(KeySpec.Type.ANY, null));
            } else if (spec.equalsIgnoreCase("noSig")) {
                specs.add(new KeySpec(KeySpec.Type.NO_SIG, null));
            } else if (spec.startsWith("0x") || spec.startsWith("0X")) {
                specs.add(new KeySpec(KeySpec.Type.GPG_FINGERPRINT, spec.substring(2).toUpperCase()));
            } else if (spec.startsWith("pqc-cert:")) {
                String path = interpolateProperties(spec.substring("pqc-cert:".length()), propertyResolver);
                specs.add(new KeySpec(KeySpec.Type.PQC_CERT, path));
            } else if (spec.startsWith("pqc:")) {
                specs.add(new KeySpec(KeySpec.Type.PQC_FINGERPRINT, spec.substring("pqc:".length())));
            }
        }
        validateKeySpecs(specs, specsStr);
        return specs;
    }

    private static void validateKeySpecs(List<KeySpec> specs, String rawLine) {
        if (specs.size() <= 1) {
            return;
        }
        boolean hasExclusive = specs.stream()
                .anyMatch(s -> s.type() == KeySpec.Type.ANY || s.type() == KeySpec.Type.NO_SIG);
        if (hasExclusive) {
            throw new IllegalArgumentException(
                    "'any' and 'noSig' cannot be combined with other key specs: " + rawLine);
        }
    }

    private static String interpolateProperties(String value, Function<String, String> propertyResolver) {
        Matcher matcher = PROPERTY_PATTERN.matcher(value);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String propName = matcher.group(1);
            String resolved = propertyResolver.apply(propName);
            String propValue = resolved != null ? resolved : matcher.group(0);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(propValue));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * A single keys.map entry mapping an artifact pattern to expected key specs.
     *
     * @param groupPattern the group ID pattern (exact match, or {@code com.example.*} for prefix)
     * @param artifactPattern the artifact ID pattern ({@code *} for any), or null to match all artifacts
     * @param keySpecs the expected key specifications for matching artifacts
     */
    public record Entry(String groupPattern, String artifactPattern, List<KeySpec> keySpecs) {
    }

    /**
     * Specifies an expected signature key for an artifact.
     *
     * @param type the key specification type
     * @param value the key value (fingerprint, file path, or null for {@code ANY}/{@code NO_SIG})
     */
    public record KeySpec(Type type, String value) {
        public enum Type {
            /** GPG key fingerprint (from {@code 0xABCD...} syntax) */
            GPG_FINGERPRINT,
            /** PQC key fingerprint (from {@code pqc:ABCD...} syntax) */
            PQC_FINGERPRINT,
            /** PQC certificate file path (from {@code pqc-cert:/path} syntax) */
            PQC_CERT,
            /** Accept any valid signature */
            ANY,
            /** No signature expected */
            NO_SIG
        }
    }
}
