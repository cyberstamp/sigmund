package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class KeyFetchCacheTest {

    @Test
    void shouldAttemptReturnsTrueByDefault() {
        var cache = new KeyFetchCache();
        assertThat(cache.shouldAttempt("hkps://keys.example.com", "ABCD1234")).isTrue();
    }

    @Test
    void connectionFailureTripsCircuitForThatServer() {
        var cache = new KeyFetchCache();
        cache.recordServerFailure("hkps://down.example.com");

        assertThat(cache.shouldAttempt("hkps://down.example.com", "ABCD1234")).isFalse();
        assertThat(cache.shouldAttempt("hkps://up.example.com", "ABCD1234")).isTrue();
    }

    @Test
    void keyNotFoundBlocksKeyAcrossServers() {
        var cache = new KeyFetchCache();
        cache.recordKeyNotFound("DEADBEEF");

        assertThat(cache.shouldAttempt("hkps://server1.example.com", "DEADBEEF")).isFalse();
        assertThat(cache.shouldAttempt("hkps://server2.example.com", "DEADBEEF")).isFalse();
        assertThat(cache.shouldAttempt("hkps://server1.example.com", "OTHER123")).isTrue();
    }

    @Test
    void successDoesNotAffectOtherKeys() {
        var cache = new KeyFetchCache();
        cache.recordSuccess("hkps://keys.example.com", "ABCD1234");

        assertThat(cache.shouldAttempt("hkps://keys.example.com", "ABCD1234")).isTrue();
        assertThat(cache.shouldAttempt("hkps://keys.example.com", "OTHER123")).isTrue();
    }

    @Test
    void circuitBreakerAndNegativeCacheCombine() {
        var cache = new KeyFetchCache();
        cache.recordServerFailure("hkps://down.example.com");
        cache.recordKeyNotFound("DEADBEEF");

        assertThat(cache.shouldAttempt("hkps://down.example.com", "DEADBEEF")).isFalse();
        assertThat(cache.shouldAttempt("hkps://down.example.com", "OTHER123")).isFalse();
        assertThat(cache.shouldAttempt("hkps://up.example.com", "DEADBEEF")).isFalse();
        assertThat(cache.shouldAttempt("hkps://up.example.com", "OTHER123")).isTrue();
    }
}
