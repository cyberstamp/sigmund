package io.github.aloubyansky.sigmund.core;

/**
 * A {@link VerifyResult} for cases where no real verification was performed.
 * <p>
 * Used when a signature file is missing ({@link Verdict#SKIPPED}) or when
 * verification fails before producing a format-specific result
 * ({@link Verdict#FAIL}).
 *
 * @see VerifyResult
 */
public final class UnverifiedResult extends VerifyResult {

    public UnverifiedResult(Verdict verdict) {
        super(verdict, null, null);
        if (verdict == Verdict.PASS) {
            throw new IllegalArgumentException("UnverifiedResult cannot have verdict PASS");
        }
    }
}
