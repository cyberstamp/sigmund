package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DefaultTrustPolicyTest {

    @Test
    void requireAllEvidenceMatch() {
        var policy = new DefaultTrustPolicy(Map.of(), List.of(), true, UntrustedPolicy.FAIL);
        assertTrue(policy.requireAllEvidenceMatch());
    }

    @Test
    void untrustedPolicy() {
        var policy = new DefaultTrustPolicy(Map.of(), List.of(), false, UntrustedPolicy.WARN);
        assertEquals(UntrustedPolicy.WARN, policy.onUntrusted());
    }
}
