package com.corp.authserver.config;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwkConfigTest {

    private JwkConfig jwkConfig;

    @BeforeEach
    void setUp() {
        jwkConfig = new JwkConfig();
    }

    @Test
    @DisplayName("FR-KEY-01: Should generate RSA key pair for JWK endpoint")
    void shouldGenerateRsaKeyPair() throws Exception {
        RSAKey rsaKey = jwkConfig.generateRsaKey();

        assertThat(rsaKey).isNotNull();
        assertThat(rsaKey.getKeyID()).isNotNull();
        assertThat(rsaKey.toRSAPublicKey()).isNotNull();
        assertThat(rsaKey.isPrivate()).isTrue();
    }

    @Test
    @DisplayName("FR-KEY-01: JWK source should expose keys for public distribution")
    void shouldExposeJwkSource() throws Exception {
        JWKSource<SecurityContext> jwkSource = jwkConfig.jwkSource();

        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().build());
        var keys = jwkSource.get(selector, null);

        assertThat(keys).isNotEmpty();
        assertThat(keys.get(0)).isInstanceOf(RSAKey.class);
    }

    @Test
    @DisplayName("FR-KEY-02: Should rotate keys without removing old ones (grace period)")
    void shouldRotateKeysWithGracePeriod() {
        jwkConfig.jwkSource(); // Initialize
        String originalKeyId = jwkConfig.getCurrentKeyId();

        jwkConfig.rotateKey();

        String newKeyId = jwkConfig.getCurrentKeyId();
        assertThat(newKeyId).isNotEqualTo(originalKeyId);
        // Old key should still be present for grace period
        assertThat(jwkConfig.getKeyMap()).containsKey(originalKeyId);
        assertThat(jwkConfig.getKeyMap()).containsKey(newKeyId);
        assertThat(jwkConfig.getKeyMap()).hasSize(2);
    }

    @Test
    @DisplayName("FR-KEY-02: Should support multiple key rotations")
    void shouldSupportMultipleRotations() {
        jwkConfig.jwkSource();

        jwkConfig.rotateKey();
        jwkConfig.rotateKey();
        jwkConfig.rotateKey();

        assertThat(jwkConfig.getKeyMap()).hasSize(4); // 1 original + 3 rotations
    }

    @Test
    @DisplayName("FR-KEY-02: Should remove old keys but never remove current key")
    void shouldRemoveOldKeysButKeepCurrent() {
        jwkConfig.jwkSource();
        String firstKeyId = jwkConfig.getCurrentKeyId();

        jwkConfig.rotateKey();
        String currentKeyId = jwkConfig.getCurrentKeyId();

        // Can remove old key
        jwkConfig.removeKey(firstKeyId);
        assertThat(jwkConfig.getKeyMap()).doesNotContainKey(firstKeyId);

        // Cannot remove current key
        jwkConfig.removeKey(currentKeyId);
        assertThat(jwkConfig.getKeyMap()).containsKey(currentKeyId);
    }

    @Test
    @DisplayName("FR-KEY-03: Generated RSA key should have public key for resource server verification")
    void shouldHavePublicKeyForVerification() throws Exception {
        RSAKey rsaKey = jwkConfig.generateRsaKey();

        // Public key should be extractable for resource servers
        RSAKey publicKey = rsaKey.toPublicJWK();
        assertThat(publicKey).isNotNull();
        assertThat(publicKey.isPrivate()).isFalse();
        assertThat(publicKey.toRSAPublicKey()).isNotNull();
    }

    @Test
    @DisplayName("FR-TOKEN-07: Key should use RSA asymmetric cryptography")
    void shouldUseRsaAsymmetricCrypto() {
        RSAKey rsaKey = jwkConfig.generateRsaKey();

        assertThat(rsaKey.getKeyType().getValue()).isEqualTo("RSA");
        assertThat(rsaKey.getKeyID()).isNotBlank();
    }

    @Test
    @DisplayName("Should track key creation time")
    void shouldTrackKeyCreationTime() {
        jwkConfig.jwkSource();
        String keyId = jwkConfig.getCurrentKeyId();

        assertThat(jwkConfig.getKeyCreationTime(keyId)).isNotNull();
    }
}
