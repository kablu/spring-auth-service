package com.corp.authserver.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenCustomizerTest {

    private JwtTokenCustomizer tokenCustomizer;

    @Mock
    private JwtEncodingContext context;

    @Mock
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        tokenCustomizer = new JwtTokenCustomizer();
    }

    @SuppressWarnings("unchecked")
    private void mockAuthorities(GrantedAuthority... authorities) {
        Collection<GrantedAuthority> authCollection = List.of(authorities);
        doReturn(authCollection).when(authentication).getAuthorities();
    }

    @Test
    @DisplayName("FR-TOKEN-06: Access token should include roles claim")
    void shouldIncludeRolesInAccessToken() {
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("test")
                .issuedAt(Instant.now());

        when(context.getPrincipal()).thenReturn(authentication);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        mockAuthorities(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN"));
        when(authentication.getName()).thenReturn("testuser");
        when(context.getAuthorizedScopes()).thenReturn(Set.of("read", "write"));
        when(context.getClaims()).thenReturn(claimsBuilder);

        tokenCustomizer.customize(context);

        JwtClaimsSet builtClaims = claimsBuilder.build();
        assertThat((Object) builtClaims.getClaim("roles")).isNotNull();
        @SuppressWarnings("unchecked")
        Set<String> roles = (Set<String>) builtClaims.getClaim("roles");
        assertThat(roles).contains("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("FR-TOKEN-06: Access token should include scopes claim")
    void shouldIncludeScopesInAccessToken() {
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("test")
                .issuedAt(Instant.now());

        when(context.getPrincipal()).thenReturn(authentication);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        mockAuthorities();
        when(authentication.getName()).thenReturn("testuser");
        when(context.getAuthorizedScopes()).thenReturn(Set.of("read", "write"));
        when(context.getClaims()).thenReturn(claimsBuilder);

        tokenCustomizer.customize(context);

        JwtClaimsSet builtClaims = claimsBuilder.build();
        @SuppressWarnings("unchecked")
        Set<String> scope = (Set<String>) builtClaims.getClaim("scope");
        assertThat(scope).contains("read", "write");
    }

    @Test
    @DisplayName("FR-TOKEN-06: Access token should include username claim")
    void shouldIncludeUsernameInAccessToken() {
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("test")
                .issuedAt(Instant.now());

        when(context.getPrincipal()).thenReturn(authentication);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        mockAuthorities();
        when(authentication.getName()).thenReturn("testuser");
        when(context.getAuthorizedScopes()).thenReturn(Set.of());
        when(context.getClaims()).thenReturn(claimsBuilder);

        tokenCustomizer.customize(context);

        JwtClaimsSet builtClaims = claimsBuilder.build();
        assertThat((String) builtClaims.getClaim("username")).isEqualTo("testuser");
    }

    @Test
    @DisplayName("FR-TOKEN-04: ID token should include roles and preferred_username")
    void shouldCustomizeIdToken() {
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("test")
                .issuedAt(Instant.now());

        when(context.getPrincipal()).thenReturn(authentication);
        when(context.getTokenType()).thenReturn(new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        mockAuthorities(new SimpleGrantedAuthority("ROLE_USER"));
        when(authentication.getName()).thenReturn("testuser");
        when(context.getClaims()).thenReturn(claimsBuilder);

        tokenCustomizer.customize(context);

        JwtClaimsSet builtClaims = claimsBuilder.build();
        assertThat((Object) builtClaims.getClaim("roles")).isNotNull();
        assertThat((String) builtClaims.getClaim("preferred_username")).isEqualTo("testuser");
    }
}
