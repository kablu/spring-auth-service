package com.corp.authserver.service;

import com.corp.authserver.config.AuthServerProperties;
import com.corp.authserver.dto.ClientRegistrationRequest;
import com.corp.authserver.dto.ClientResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientManagementServiceTest {

    private ClientManagementService service;
    private RegisteredClientRepository clientRepository;

    @BeforeEach
    void setUp() {
        // Create a minimal repo with a dummy client (InMemoryRegisteredClientRepository requires at least one)
        RegisteredClient dummyClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("dummy-init")
                .clientSecret("{noop}dummy")
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scope("read")
                .build();
        clientRepository = new InMemoryRegisteredClientRepository(dummyClient);

        AuthServerProperties properties = new AuthServerProperties();
        properties.getToken().setAccessTokenValiditySeconds(3600);
        properties.getToken().setRefreshTokenValiditySeconds(2592000);
        properties.getToken().setReuseRefreshTokens(false);

        service = new ClientManagementService(clientRepository, properties);
    }

    @Test
    @DisplayName("FR-CLIENT-01: Should register a new OAuth2 client")
    void shouldRegisterNewClient() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("test-client")
                .clientSecret("test-secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read", "write"))
                .build();

        ClientResponse response = service.registerClient(request);

        assertThat(response).isNotNull();
        assertThat(response.getClientId()).isEqualTo("test-client");
        assertThat(response.getAuthorizationGrantTypes()).contains("client_credentials");
        assertThat(response.getScopes()).contains("read", "write");
    }

    @Test
    @DisplayName("FR-CLIENT-01: Should register client with authorization_code grant and redirect URIs")
    void shouldRegisterClientWithAuthCode() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("auth-code-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("authorization_code", "refresh_token"))
                .redirectUris(Set.of("http://localhost:8080/callback"))
                .scopes(Set.of("openid", "profile"))
                .requireProofKey(true)
                .build();

        ClientResponse response = service.registerClient(request);

        assertThat(response.getAuthorizationGrantTypes()).contains("authorization_code", "refresh_token");
        assertThat(response.getRedirectUris()).contains("http://localhost:8080/callback");
        assertThat(response.isRequireProofKey()).isTrue();
    }

    @Test
    @DisplayName("FR-CLIENT-02: Should support client_secret_basic authentication")
    void shouldSupportClientSecretBasic() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("basic-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        ClientResponse response = service.registerClient(request);
        assertThat(response.getClientAuthenticationMethods()).contains("client_secret_basic");
    }

    @Test
    @DisplayName("FR-CLIENT-02: Should support private_key_jwt authentication")
    void shouldSupportPrivateKeyJwt() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("jwt-client")
                .authenticationMethods(Set.of("private_key_jwt"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        ClientResponse response = service.registerClient(request);
        assertThat(response.getClientAuthenticationMethods()).contains("private_key_jwt");
    }

    @Test
    @DisplayName("FR-CLIENT-02: Should support mTLS authentication")
    void shouldSupportMtls() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("mtls-client")
                .authenticationMethods(Set.of("tls_client_auth"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        ClientResponse response = service.registerClient(request);
        assertThat(response.getClientAuthenticationMethods()).contains("tls_client_auth");
    }

    @Test
    @DisplayName("FR-CLIENT-03: Should enforce redirect URI validation for authorization_code grant")
    void shouldEnforceRedirectUriForAuthCode() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("no-redirect-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("authorization_code"))
                .scopes(Set.of("openid"))
                .build();

        assertThatThrownBy(() -> service.registerClient(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Redirect URIs required");
    }

    @Test
    @DisplayName("FR-GRANT-04: Should reject deprecated password grant type")
    void shouldRejectPasswordGrant() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("bad-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("password"))
                .scopes(Set.of("read"))
                .build();

        assertThatThrownBy(() -> service.registerClient(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Deprecated grant type");
    }

    @Test
    @DisplayName("FR-GRANT-04: Should reject deprecated implicit grant type")
    void shouldRejectImplicitGrant() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("bad-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("implicit"))
                .scopes(Set.of("read"))
                .build();

        assertThatThrownBy(() -> service.registerClient(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Deprecated grant type");
    }

    @Test
    @DisplayName("Should reject unsupported grant types")
    void shouldRejectUnsupportedGrantType() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("bad-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("device_code"))
                .scopes(Set.of("read"))
                .build();

        assertThatThrownBy(() -> service.registerClient(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported grant type");
    }

    @Test
    @DisplayName("Should retrieve registered client by clientId")
    void shouldRetrieveClient() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("retrievable-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        service.registerClient(request);
        ClientResponse response = service.getClient("retrievable-client");

        assertThat(response).isNotNull();
        assertThat(response.getClientId()).isEqualTo("retrievable-client");
    }

    @Test
    @DisplayName("Should throw exception for non-existent client")
    void shouldThrowForNonExistentClient() {
        assertThatThrownBy(() -> service.getClient("nonexistent"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client not found");
    }

    @Test
    @DisplayName("FR-TOKEN-05: Should use custom token validity when specified")
    void shouldUseCustomTokenValidity() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("custom-ttl-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .accessTokenValiditySeconds(1800)
                .refreshTokenValiditySeconds(86400)
                .build();

        ClientResponse response = service.registerClient(request);

        assertThat(response.getAccessTokenTtlSeconds()).isEqualTo(1800);
        assertThat(response.getRefreshTokenTtlSeconds()).isEqualTo(86400);
    }

    @Test
    @DisplayName("FR-TOKEN-05: Should use default token validity when not specified")
    void shouldUseDefaultTokenValidity() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("default-ttl-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        ClientResponse response = service.registerClient(request);

        assertThat(response.getAccessTokenTtlSeconds()).isEqualTo(3600);
        assertThat(response.getRefreshTokenTtlSeconds()).isEqualTo(2592000);
    }

    @Test
    @DisplayName("Should reject unsupported authentication method")
    void shouldRejectUnsupportedAuthMethod() {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("bad-auth-client")
                .authenticationMethods(Set.of("unsupported_method"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        assertThatThrownBy(() -> service.registerClient(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported authentication method");
    }
}
