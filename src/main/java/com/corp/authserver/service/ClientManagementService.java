package com.corp.authserver.service;

import com.corp.authserver.config.AuthServerProperties;
import com.corp.authserver.dto.ClientRegistrationRequest;
import com.corp.authserver.dto.ClientResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientManagementService {

    private final RegisteredClientRepository clientRepository;
    private final AuthServerProperties properties;

    private static final Set<String> ALLOWED_GRANT_TYPES = Set.of(
            "authorization_code", "client_credentials", "refresh_token"
    );

    private static final Set<String> DEPRECATED_GRANT_TYPES = Set.of(
            "password", "implicit"
    );

    public ClientResponse registerClient(ClientRegistrationRequest request) {
        validateGrantTypes(request.getGrantTypes());
        validateRedirectUris(request);

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(request.getClientId());

        if (request.getClientSecret() != null && !request.getClientSecret().isBlank()) {
            builder.clientSecret("{noop}" + request.getClientSecret());
        }

        for (String method : request.getAuthenticationMethods()) {
            builder.clientAuthenticationMethod(resolveAuthMethod(method));
        }

        for (String grantType : request.getGrantTypes()) {
            builder.authorizationGrantType(resolveGrantType(grantType));
        }

        if (request.getRedirectUris() != null) {
            request.getRedirectUris().forEach(builder::redirectUri);
        }

        if (request.getScopes() != null) {
            request.getScopes().forEach(builder::scope);
        }

        int accessTokenTtl = request.getAccessTokenValiditySeconds() != null
                ? request.getAccessTokenValiditySeconds()
                : properties.getToken().getAccessTokenValiditySeconds();
        int refreshTokenTtl = request.getRefreshTokenValiditySeconds() != null
                ? request.getRefreshTokenValiditySeconds()
                : properties.getToken().getRefreshTokenValiditySeconds();

        builder.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(accessTokenTtl))
                .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTtl))
                .reuseRefreshTokens(properties.getToken().isReuseRefreshTokens())
                .build());

        builder.clientSettings(ClientSettings.builder()
                .requireProofKey(request.isRequireProofKey())
                .requireAuthorizationConsent(request.isRequireAuthorizationConsent())
                .build());

        RegisteredClient registeredClient = builder.build();
        clientRepository.save(registeredClient);
        log.info("Registered new OAuth2 client: {}", request.getClientId());

        return toResponse(registeredClient);
    }

    public ClientResponse getClient(String clientId) {
        RegisteredClient client = clientRepository.findByClientId(clientId);
        if (client == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
        }
        return toResponse(client);
    }

    private void validateGrantTypes(Set<String> grantTypes) {
        for (String grantType : grantTypes) {
            if (DEPRECATED_GRANT_TYPES.contains(grantType)) {
                throw new IllegalArgumentException("Deprecated grant type not supported: " + grantType);
            }
            if (!ALLOWED_GRANT_TYPES.contains(grantType)) {
                throw new IllegalArgumentException("Unsupported grant type: " + grantType);
            }
        }
    }

    private void validateRedirectUris(ClientRegistrationRequest request) {
        if (request.getGrantTypes().contains("authorization_code")
                && (request.getRedirectUris() == null || request.getRedirectUris().isEmpty())) {
            throw new IllegalArgumentException("Redirect URIs required for authorization_code grant type");
        }
    }

    private ClientAuthenticationMethod resolveAuthMethod(String method) {
        return switch (method.toLowerCase()) {
            case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            case "none" -> ClientAuthenticationMethod.NONE;
            case "tls_client_auth" -> new ClientAuthenticationMethod("tls_client_auth");
            default -> throw new IllegalArgumentException("Unsupported authentication method: " + method);
        };
    }

    private AuthorizationGrantType resolveGrantType(String grantType) {
        return switch (grantType.toLowerCase()) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            default -> throw new IllegalArgumentException("Unsupported grant type: " + grantType);
        };
    }

    private ClientResponse toResponse(RegisteredClient client) {
        return ClientResponse.builder()
                .id(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientAuthenticationMethods(
                        client.getClientAuthenticationMethods().stream()
                                .map(ClientAuthenticationMethod::getValue)
                                .collect(Collectors.toSet()))
                .authorizationGrantTypes(
                        client.getAuthorizationGrantTypes().stream()
                                .map(AuthorizationGrantType::getValue)
                                .collect(Collectors.toSet()))
                .redirectUris(client.getRedirectUris())
                .scopes(client.getScopes())
                .requireProofKey(client.getClientSettings().isRequireProofKey())
                .requireAuthorizationConsent(client.getClientSettings().isRequireAuthorizationConsent())
                .accessTokenTtlSeconds(client.getTokenSettings().getAccessTokenTimeToLive().getSeconds())
                .refreshTokenTtlSeconds(client.getTokenSettings().getRefreshTokenTimeToLive() != null
                        ? client.getTokenSettings().getRefreshTokenTimeToLive().getSeconds()
                        : null)
                .build();
    }
}
