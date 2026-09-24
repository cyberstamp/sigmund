package dev.cyberstamp.sigmund.core;

/**
 * What to do with claims beyond those that satisfied a rule's requirements.
 */
public enum ClaimSetMode {

    /**
     * Every remaining claim must also verify and be accepted by policy. The default, matching
     * RPMv6's rule that every signature on a package must verify: evidence that does not belong
     * is a question, not noise.
     */
    ALL_CLAIMS,

    /**
     * Claims beyond those needed are recorded and ignored. The deliberate exception, for
     * artifacts carrying signatures from parties a policy does not speak about.
     */
    ANY_CLAIM
}
