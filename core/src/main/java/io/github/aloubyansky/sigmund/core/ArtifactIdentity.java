package io.github.aloubyansky.sigmund.core;

/**
 * A generic artifact identity not tied to any package manager.
 * <p>
 * Carries only the universally shared fields needed for trust policy matching.
 * Ecosystem-specific implementations add their own fields — for example, a Maven
 * implementation adds {@code type} and {@code classifier}.
 * <p>
 * Trust configuration patterns use a colon-separated format with 1–3 parts
 * mapping directly to these fields: {@code namespace}, {@code namespace:name},
 * or {@code namespace:name:version}.
 *
 * <h3>Ecosystem mapping</h3>
 * <table>
 * <tr>
 * <th>Field</th>
 * <th>Maven</th>
 * <th>npm</th>
 * <th>OCI</th>
 * </tr>
 * <tr>
 * <td>{@code namespace}</td>
 * <td>groupId</td>
 * <td>scope</td>
 * <td>registry/org</td>
 * </tr>
 * <tr>
 * <td>{@code name}</td>
 * <td>artifactId</td>
 * <td>package name</td>
 * <td>image name</td>
 * </tr>
 * <tr>
 * <td>{@code version}</td>
 * <td>version</td>
 * <td>version</td>
 * <td>tag</td>
 * </tr>
 * </table>
 */
public interface ArtifactIdentity {

    /**
     * Returns the namespace of this artifact (e.g., Maven groupId).
     *
     * @return the namespace, never {@code null}
     */
    String namespace();

    /**
     * Returns the name of this artifact (e.g., Maven artifactId).
     *
     * @return the name, never {@code null}
     */
    String name();

    /**
     * Returns the version of this artifact.
     *
     * @return the version, never {@code null}
     */
    String version();
}
