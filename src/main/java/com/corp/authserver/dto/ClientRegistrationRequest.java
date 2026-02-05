package com.corp.authserver.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationRequest {

    @NotBlank(message = "Client ID is required")
    private String clientId;

    private String clientSecret;

    @NotEmpty(message = "At least one authentication method is required")
    private Set<String> authenticationMethods;

    @NotEmpty(message = "At least one grant type is required")
    private Set<String> grantTypes;

    private Set<String> redirectUris;

    private Set<String> scopes;

    private boolean requireProofKey;

    private boolean requireAuthorizationConsent;

    private Integer accessTokenValiditySeconds;

    private Integer refreshTokenValiditySeconds;
}
