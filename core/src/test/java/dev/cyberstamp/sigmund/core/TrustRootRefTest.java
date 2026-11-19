package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class TrustRootRefTest {

    @Test
    void namesTheCertDStoreThatAnsweredAndWhere() {
        TrustRootRef ref = TrustRootRef.certD(Path.of("/home/u/.local/share/pgp.cert.d"));

        assertThat(ref.kind()).isEqualTo(TrustRootRef.KIND_OPENPGP_CERT_D);
        assertThat(ref.identifier()).isEqualTo("/home/u/.local/share/pgp.cert.d");
    }

    @Test
    void distinguishesAGnupgKeyringFromACertDStore() {
        assertThat(TrustRootRef.gnupgKeyring(Path.of("/home/u/.gnupg")).kind())
                .isEqualTo(TrustRootRef.KIND_GNUPG_KEYRING);
        assertThat(TrustRootRef.bcPrivateStore(Path.of("/home/u/bc-private")).kind())
                .isEqualTo(TrustRootRef.KIND_BC_PRIVATE_STORE);
    }

    @Test
    void displaysKindAndLocation() {
        assertThat(TrustRootRef.keyserver("hkps://keys.openpgp.org").displayName())
                .isEqualTo("openpgp-keyserver hkps://keys.openpgp.org");
        assertThat(TrustRootRef.unknown().displayName()).isEqualTo(TrustRootRef.KIND_UNKNOWN);
    }

    @Test
    void severalKeyserversAreListedInOrder() {
        TrustRootRef ref = TrustRootRef.keyservers(List.of("hkps://a.example", "hkps://b.example"));

        assertThat(ref.kind()).isEqualTo(TrustRootRef.KIND_OPENPGP_KEYSERVER);
        assertThat(ref.identifier()).isEqualTo("hkps://a.example, hkps://b.example");
    }

    @Test
    void oneKeyserverReadsAsBefore() {
        assertThat(TrustRootRef.keyservers(List.of("hkps://a.example")))
                .isEqualTo(TrustRootRef.keyserver("hkps://a.example"));
    }

    @Test
    void noKeyserverIsRejected() {
        assertThatThrownBy(() -> TrustRootRef.keyservers(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aMissingListOfKeyserversIsRejected() {
        assertThatThrownBy(() -> TrustRootRef.keyservers(null))
                .isInstanceOf(IllegalArgumentException.class);
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
