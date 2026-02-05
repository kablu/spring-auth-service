package com.corp.authserver.service;

import com.corp.authserver.config.AuthServerProperties;
import com.corp.authserver.config.JwkConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KeyRotationServiceTest {

    private KeyRotationService keyRotationService;
    private JwkConfig jwkConfig;
    private AuthServerProperties properties;

    @BeforeEach
    void setUp() {
        jwkConfig = new JwkConfig();
        jwkConfig.jwkSource(); // Initialize keys

        properties = new AuthServerProperties();
        properties.getKeyRotation().setEnabled(true);
        properties.getKeyRotation().setRotationDays(90);
        properties.getKeyRotation().setGracePeriodDays(7);

        keyRotationService = new KeyRotationService(jwkConfig, properties);
    }

    @Test
    @DisplayName("FR-KEY-02: Should rotate keys on demand")
    void shouldRotateKeys() {
        String originalKeyId = keyRotationService.getCurrentKeyId();

        keyRotationService.rotateKeys();

        String newKeyId = keyRotationService.getCurrentKeyId();
        assertThat(newKeyId).isNotEqualTo(originalKeyId);
        assertThat(keyRotationService.getActiveKeyCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("FR-KEY-02: Should not rotate keys when rotation is disabled")
    void shouldNotRotateWhenDisabled() {
        properties.getKeyRotation().setEnabled(false);
        String originalKeyId = keyRotationService.getCurrentKeyId();

        keyRotationService.checkAndRotateKeys();

        assertThat(keyRotationService.getCurrentKeyId()).isEqualTo(originalKeyId);
        assertThat(keyRotationService.getActiveKeyCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("FR-KEY-02: Should not rotate keys when within threshold")
    void shouldNotRotateWhenWithinThreshold() {
        String originalKeyId = keyRotationService.getCurrentKeyId();
        // Key was just created, so it's well within 90-day threshold
        keyRotationService.checkAndRotateKeys();

        assertThat(keyRotationService.getCurrentKeyId()).isEqualTo(originalKeyId);
    }

    @Test
    @DisplayName("FR-KEY-02: Should keep both old and new keys after rotation")
    void shouldKeepBothKeysAfterRotation() {
        keyRotationService.rotateKeys();
        keyRotationService.rotateKeys();

        assertThat(keyRotationService.getActiveKeyCount()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should return correct active key count")
    void shouldReturnActiveKeyCount() {
        assertThat(keyRotationService.getActiveKeyCount()).isEqualTo(1);

        keyRotationService.rotateKeys();
        assertThat(keyRotationService.getActiveKeyCount()).isEqualTo(2);
    }
}
