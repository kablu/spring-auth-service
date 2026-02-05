package com.corp.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Spring OAuth2 Authorization Server Application
 *
 * Features:
 * - OAuth2 Authorization Server with JWT tokens
 * - Active Directory / LDAP authentication
 * - Custom JWT claims (roles, scopes, user attributes)
 * - Multiple OAuth2 grant types (Authorization Code + PKCE, Client Credentials, Refresh Token)
 * - Token revocation and refresh token rotation
 * - JWK endpoint for public key distribution
 * - Key rotation support
 * - PKCE enforcement for public clients
 * - HTTPS enforcement (production)
 * - CSRF protection
 * - Rate limiting
 *
 * @author Claude Sonnet 4.5
 * @version 1.0.0
 * @since 2026-02-04
 */
@SpringBootApplication
@EnableScheduling
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
        System.out.println("""

            ╔═══════════════════════════════════════════════════════════╗
            ║  Spring OAuth2 Authorization Server Started              ║
            ║                                                           ║
            ║  OAuth2 Endpoints:                                        ║
            ║    - Authorization: /oauth2/authorize                     ║
            ║    - Token:         /oauth2/token                         ║
            ║    - JWK Set:       /oauth2/jwks                          ║
            ║    - Revoke:        /oauth2/revoke                        ║
            ║    - Introspect:    /oauth2/introspect                    ║
            ║                                                           ║
            ║  Discovery Endpoints:                                     ║
            ║    - /.well-known/oauth-authorization-server              ║
            ║    - /.well-known/openid-configuration                    ║
            ║                                                           ║
            ║  Management API:                                          ║
            ║    - /actuator/health                                     ║
            ║    - /actuator/metrics                                    ║
            ║    - /api/clients (Client Management)                     ║
            ║                                                           ║
            ║  Documentation:                                           ║
            ║    - /swagger-ui.html                                     ║
            ║                                                           ║
            ║  Status: Ready to authenticate!                           ║
            ╚═══════════════════════════════════════════════════════════╝
            """);
    }
}
