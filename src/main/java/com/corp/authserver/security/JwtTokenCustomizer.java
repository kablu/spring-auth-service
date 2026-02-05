package com.corp.authserver.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        String tokenType = context.getTokenType().getValue();

        if (OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType)) {
            customizeAccessToken(context, principal);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType)) {
            customizeIdToken(context, principal);
        }
    }

    private void customizeAccessToken(JwtEncodingContext context, Authentication principal) {
        Set<String> roles = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        context.getClaims().claims(claims -> {
            claims.put("roles", roles);
            claims.put("token_type", "access_token");

            Set<String> scopes = context.getAuthorizedScopes();
            if (scopes != null && !scopes.isEmpty()) {
                claims.put("scope", scopes);
            }

            if (principal.getName() != null) {
                claims.put("username", principal.getName());
            }
        });

        log.debug("Customized access token for user: {} with roles: {}", principal.getName(), roles);
    }

    private void customizeIdToken(JwtEncodingContext context, Authentication principal) {
        Set<String> roles = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        context.getClaims().claims(claims -> {
            claims.put("roles", roles);

            if (principal.getName() != null) {
                claims.put("preferred_username", principal.getName());
            }
        });

        log.debug("Customized ID token for user: {}", principal.getName());
    }
}
