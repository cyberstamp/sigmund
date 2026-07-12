package io.github.aloubyansky.sigmund.core;

/**
 * Base exception for all Sigmund errors.
 * <p>
 * Sigmund distinguishes between <em>verification outcomes</em> (represented as result objects
 * such as {@link EvidenceResult} and {@link TrustResult}) and <em>infrastructure failures</em>
 * (represented as exceptions). This exception and its subclasses cover infrastructure failures —
 * situations where an operation could not be attempted or completed.
 *
 * @see ToolExecutionException
 * @see PolicyConfigException
 */
public class SigmundException extends RuntimeException {

    /**
     * Creates a new exception with the given message.
     *
     * @param message a description of the error
     */
    public SigmundException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param message a description of the error
     * @param cause the underlying cause
     */
    public SigmundException(String message, Throwable cause) {
        super(message, cause);
    }
}
