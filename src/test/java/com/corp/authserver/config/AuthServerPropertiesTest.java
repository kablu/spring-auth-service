package com.corp.authserver.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class AuthServerPropertiesTest {

    @Autowired
    private AuthServerProperties properties;

    @Test
    @DisplayName("FR-TOKEN-05: Access token expiry should be configurable")
    void shouldHaveConfigurableAccessTokenExpiry() {
        assertThat(properties.getToken().getAccessTokenValiditySeconds()).isEqualTo(300);
    }

    @Test
    @DisplayName("FR-TOKEN-05: Refresh token expiry should be configurable")
    void shouldHaveConfigurableRefreshTokenExpiry() {
        assertThat(properties.getToken().getRefreshTokenValiditySeconds()).isEqualTo(600);
    }

    @Test
    @DisplayName("FR-TOKEN-05: ID token expiry should be configurable")
    void shouldHaveConfigurableIdTokenExpiry() {
        assertThat(properties.getToken().getIdTokenValiditySeconds()).isEqualTo(300);
    }

    @Test
    @DisplayName("FR-SEC-02: Refresh token rotation should be configurable")
    void shouldHaveConfigurableRefreshTokenRotation() {
        assertThat(properties.getToken().isReuseRefreshTokens()).isFalse();
    }

    @Test
    @DisplayName("FR-SEC-05: PKCE enforcement for public clients should be configurable")
    void shouldHaveConfigurablePkceEnforcement() {
        assertThat(properties.getSecurity().isPkceRequiredForPublicClients()).isTrue();
    }

    @Test
    @DisplayName("FR-SEC-03: HTTPS enforcement should be configurable")
    void shouldHaveConfigurableHttpsEnforcement() {
        assertThat(properties.getSecurity().isRequireHttps()).isFalse(); // test profile
    }

    @Test
    @DisplayName("FR-SEC-04: CSRF protection should be configurable")
    void shouldHaveConfigurableCsrfProtection() {
        // In test profile CSRF is disabled for testing ease
        assertThat(properties.getSecurity().isCsrfProtectionEnabled()).isFalse();
    }

    @Test
    @DisplayName("JWT issuer should be configurable")
    void shouldHaveConfigurableIssuer() {
        assertThat(properties.getJwt().getIssuer()).isEqualTo("http://localhost:9000");
    }

    @Test
    @DisplayName("Key rotation settings should be configurable")
    void shouldHaveConfigurableKeyRotation() {
        assertThat(properties.getKeyRotation().isEnabled()).isFalse();
        assertThat(properties.getKeyRotation().getRotationDays()).isEqualTo(1);
        assertThat(properties.getKeyRotation().getGracePeriodDays()).isEqualTo(1);
    }
}
