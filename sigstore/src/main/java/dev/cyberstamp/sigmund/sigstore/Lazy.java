package dev.cyberstamp.sigmund.sigstore;

/**
 * A value built the first time it is asked for, and at most once.
 *
 * <p>
 * Sigstore's signer and verifier fetch the trust root over the network when they are built, so
 * a tool that is built but never asked to sign or verify — every Sigstore tool of a CLI command
 * that touches no bundle — never fetches it. A failure is kept as well as a value: the next
 * request rethrows it rather than waiting on the network again, so a build with many bundles and
 * no network fails each one at once.
 *
 * @param <T> the value's type
 */
final class Lazy<T> {

    /** Builds the value; may fail. */
    @FunctionalInterface
    interface Builder<T> {

        /**
         * Builds the value.
         *
         * @return the value
         * @throws Exception when it cannot be built
         */
        T build() throws Exception;
    }

    private final Builder<T> builder;
    private boolean built;
    private T value;
    private Exception failure;

    private Lazy(Builder<T> builder) {
        this.builder = builder;
    }

    /**
     * A value built by {@code builder} when it is first asked for.
     *
     * @param builder builds the value
     * @param <T> the value's type
     * @return the lazy value
     */
    static <T> Lazy<T> of(Builder<T> builder) {
        return new Lazy<>(builder);
    }

    /**
     * A value already built.
     *
     * @param value the value
     * @param <T> the value's type
     * @return the lazy value, built
     */
    static <T> Lazy<T> built(T value) {
        Lazy<T> lazy = new Lazy<>(() -> value);
        lazy.built = true;
        lazy.value = value;
        return lazy;
    }

    /**
     * Returns the value, building it on the first call.
     *
     * @return the value
     * @throws Exception the failure building it, on this call and every later one
     */
    synchronized T get() throws Exception {
        if (!built) {
            try {
                value = builder.build();
            } catch (Exception e) {
                failure = e;
            }
            built = true;
        }
        if (failure != null) {
            throw failure;
        }
        return value;
    }

    /**
     * Returns the value if it was built, without building it.
     *
     * @return the value, or {@code null} when it was not built or failed to be
     */
    synchronized T ifBuilt() {
        return built && failure == null ? value : null;
    }
}
