package dev.cyberstamp.sigmund.sigstore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class LazyTest {

    private final AtomicInteger builds = new AtomicInteger();

    @Test
    void isNotBuiltUntilAskedFor() {
        Lazy<String> lazy = Lazy.of(() -> "v" + builds.incrementAndGet());

        assertThat(lazy.ifBuilt()).isNull();
        assertThat(builds).hasValue(0);
    }

    @Test
    void isBuiltOnceForEveryRequest() throws Exception {
        Lazy<String> lazy = Lazy.of(() -> "v" + builds.incrementAndGet());

        assertThat(lazy.get()).isEqualTo("v1");
        assertThat(lazy.get()).isEqualTo("v1");
        assertThat(lazy.ifBuilt()).isEqualTo("v1");
        assertThat(builds).hasValue(1);
    }

    /** A trust root that could not be fetched is not fetched again for the next bundle. */
    @Test
    void aFailureIsRethrownWithoutBuildingAgain() {
        IOException offline = new IOException("tuf-repo-cdn.sigstore.dev unreachable");
        Lazy<String> lazy = Lazy.of(() -> {
            builds.incrementAndGet();
            throw offline;
        });

        assertThatThrownBy(lazy::get).isSameAs(offline);
        assertThatThrownBy(lazy::get).isSameAs(offline);
        assertThat(lazy.ifBuilt()).isNull();
        assertThat(builds).hasValue(1);
    }

    @Test
    void aBuiltValueNeedsNoBuilding() throws Exception {
        Lazy<String> lazy = Lazy.built("given");

        assertThat(lazy.ifBuilt()).isEqualTo("given");
        assertThat(lazy.get()).isEqualTo("given");
    }
}
