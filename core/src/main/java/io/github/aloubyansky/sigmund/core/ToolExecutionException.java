package io.github.aloubyansky.sigmund.core;

/**
 * Thrown when a signing or verification tool fails at the infrastructure level.
 * <p>
 * This covers situations where verification cannot be attempted — for example,
 * a CLI tool (GPG, sq) is not found, crashes mid-operation, or encounters an I/O error.
 * It does <em>not</em> cover verification outcomes like an invalid signature or a missing key,
 * which are represented as result objects with appropriate status values.
 *
 * @see SigmundException
 */
public class ToolExecutionException extends SigmundException {

    /**
     * Creates a new exception with the given message.
     *
     * @param message a description of the tool failure
     */
    public ToolExecutionException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param message a description of the tool failure
     * @param cause the underlying cause (e.g., {@link java.io.IOException})
     */
    public ToolExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
