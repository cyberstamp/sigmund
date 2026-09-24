package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class TrustRootRefTest {

    @Test
    void namesTheKeyringThatAnsweredAndWhere() {
        TrustRootRef ref = TrustRootRef.keyring(Path.of("/home/u/.local/share/pgp.cert.d"));

        assertThat(ref.kind()).isEqualTo(TrustRootRef.KIND_OPENPGP_KEYRING);
        assertThat(ref.identifier()).isEqualTo("/home/u/.local/share/pgp.cert.d");
    }

    @Test
    void namesTheSigstoreTrustRoot() {
        TrustRootRef ref = TrustRootRef.sigstore("public-good");

        assertThat(ref.kind()).isEqualTo(TrustRootRef.KIND_SIGSTORE_TRUST_ROOT);
        assertThat(ref.identifier()).isEqualTo("public-good");
    }

    @Test
    void anUnknownRootIsStillRecorded() {
        assertThat(TrustRootRef.unknown().kind()).isEqualTo(TrustRootRef.KIND_UNKNOWN);
    }
}
