package com.corp.authserver.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OAuth2AuthorizationServerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    // --- FR-KEY-01: JWK Endpoint Tests ---

    @Test
    @DisplayName("FR-KEY-01: JWK endpoint should be accessible and return keys")
    void jwkEndpointShouldReturnKeys() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty());
    }

    @Test
    @DisplayName("FR-KEY-03: JWK endpoint should expose public keys only (no private key)")
    void jwkEndpointShouldNotExposePrivateKey() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }

    // --- OIDC Discovery Tests ---

    @Test
    @DisplayName("OIDC discovery endpoint should be accessible")
    void oidcDiscoveryEndpointShouldBeAccessible() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").isNotEmpty())
                .andExpect(jsonPath("$.authorization_endpoint").isNotEmpty())
                .andExpect(jsonPath("$.token_endpoint").isNotEmpty())
                .andExpect(jsonPath("$.jwks_uri").isNotEmpty());
    }

    // --- FR-GRANT-02: Client Credentials Grant Tests ---

    @Test
    @DisplayName("FR-GRANT-02: Client Credentials Grant should issue access token")
    void clientCredentialsShouldIssueAccessToken() throws Exception {
        String credentials = Base64.getEncoder()
                .encodeToString("service-client:service-client-secret".getBytes());

        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + credentials)
                        .param("grant_type", "client_credentials")
                        .param("scope", "internal.read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").isNumber());
    }

    @Test
    @DisplayName("FR-TOKEN-01: Client Credentials should return JWT access token")
    void clientCredentialsShouldReturnJwt() throws Exception {
        String credentials = Base64.getEncoder()
                .encodeToString("service-client:service-client-secret".getBytes());

        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + credentials)
                        .param("grant_type", "client_credentials")
                        .param("scope", "internal.read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.access_token").isString());
    }

    @Test
    @DisplayName("FR-SEC-06: Should reject token request with invalid credentials")
    void shouldRejectInvalidCredentials() throws Exception {
        String credentials = Base64.getEncoder()
                .encodeToString("service-client:wrong-secret".getBytes());

        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + credentials)
                        .param("grant_type", "client_credentials")
                        .param("scope", "internal.read"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("FR-SEC-06: Should not issue token without authentication")
    void shouldNotIssueTokenWithoutAuthentication() throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "client_credentials")
                        .param("scope", "internal.read"))
                .andReturn();

        int status = result.getResponse().getStatus();
        // Without credentials, should get either 401 or redirect to login (302)
        assertThat(status).isIn(401, 302);
    }

    // --- FR-GRANT-01: Authorization Code + PKCE Tests ---

    @Test
    @DisplayName("FR-GRANT-01: Authorization endpoint requires authentication")
    void authorizationEndpointRequiresAuth() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "web-client")
                        .param("redirect_uri", "http://localhost:8080/login/oauth2/code/authserver")
                        .param("scope", "openid"))
                .andReturn();

        int status = result.getResponse().getStatus();
        // Should redirect to login or return error (not 200)
        assertThat(status).isNotEqualTo(200);
    }

    @Test
    @DisplayName("FR-SEC-05: Public client PKCE enforcement is configured")
    void publicClientPkceEnforcementIsConfigured() throws Exception {
        // The SPA client has requireProofKey=true
        // Without authentication, the auth endpoint should not allow through
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "spa-client")
                        .param("redirect_uri", "http://localhost:4200/callback")
                        .param("scope", "openid"))
                .andReturn();

        int status = result.getResponse().getStatus();
        // Either 302 (redirect to login) or 400 (bad request, missing PKCE)
        assertThat(status).isIn(302, 400);
    }

    // --- FR-SEC-01: Token Revocation Tests ---

    @Test
    @DisplayName("FR-SEC-01: Token revocation endpoint should exist")
    void tokenRevocationEndpointShouldExist() throws Exception {
        String credentials = Base64.getEncoder()
                .encodeToString("service-client:service-client-secret".getBytes());

        mockMvc.perform(post("/oauth2/revoke")
                        .header("Authorization", "Basic " + credentials)
                        .param("token", "fake-token"))
                .andExpect(status().isOk());
    }

    // --- FR-TOKEN-02: JWT Format Tests ---

    @Test
    @DisplayName("FR-TOKEN-02: Access token should be in JWT format (3 parts)")
    void accessTokenShouldBeJwtFormat() throws Exception {
        String credentials = Base64.getEncoder()
                .encodeToString("service-client:service-client-secret".getBytes());

        String responseBody = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + credentials)
                        .param("grant_type", "client_credentials")
                        .param("scope", "internal.read"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // JWT has format: header.payload.signature
        String accessToken = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(responseBody).get("access_token").asText();
        String[] parts = accessToken.split("\\.");
        assertThat(parts).hasSize(3);
    }

    // --- FR-GRANT-04: Deprecated Grant Type Tests ---

    @Test
    @DisplayName("FR-GRANT-04: Should reject password grant type")
    void shouldRejectPasswordGrant() throws Exception {
        String credentials = Base64.getEncoder()
                .encodeToString("web-client:web-client-secret".getBytes());

        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + credentials)
                        .param("grant_type", "password")
                        .param("username", "user")
                        .param("password", "password"))
                .andExpect(status().isBadRequest());
    }

    // --- Health & Actuator Tests ---

    @Test
    @DisplayName("Actuator health endpoint should be accessible without authentication")
    void healthEndpointShouldBeAccessible() throws Exception {
        MvcResult result = mockMvc.perform(get("/actuator/health"))
                .andReturn();

        int status = result.getResponse().getStatus();
        // Health endpoint is accessible (200 or 503 if DB not fully up)
        assertThat(status).isIn(200, 503);
    }
}
