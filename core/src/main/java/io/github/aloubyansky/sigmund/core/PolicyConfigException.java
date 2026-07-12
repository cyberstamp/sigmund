package io.github.aloubyansky.sigmund.core;

/**
 * Thrown when trust policy or signing configuration is invalid.
 * <p>
 * Configuration errors are detected at parse time or during builder construction,
 * not deferred to verification time. Examples include malformed YAML, references to
 * undefined signers, or ambiguous credential-to-tool routing.
 *
 * @see SigmundException
 */
public class PolicyConfigException extends SigmundException {

    /**
     * Creates a new exception with the given message.
     *
     * @param message a description of the configuration error
     */
    public PolicyConfigException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param message a description of the configuration error
     * @param cause the underlying cause
     */
    public PolicyConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
