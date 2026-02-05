package com.corp.authserver.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientResponse {

    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private Set<String> clientAuthenticationMethods;
    private Set<String> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private boolean requireProofKey;
    private boolean requireAuthorizationConsent;
    private Long accessTokenTtlSeconds;
    private Long refreshTokenTtlSeconds;
}
