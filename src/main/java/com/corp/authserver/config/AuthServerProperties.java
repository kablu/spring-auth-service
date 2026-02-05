package com.corp.authserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "authserver")
public class AuthServerProperties {

    private TokenProperties token = new TokenProperties();
    private JwtProperties jwt = new JwtProperties();
    private KeyRotationProperties keyRotation = new KeyRotationProperties();
    private SecurityProperties security = new SecurityProperties();
    private RateLimitProperties rateLimit = new RateLimitProperties();
    private CorsProperties cors = new CorsProperties();

    @Data
    public static class TokenProperties {
        private int accessTokenValiditySeconds = 3600;
        private int refreshTokenValiditySeconds = 2592000;
        private int idTokenValiditySeconds = 3600;
        private boolean reuseRefreshTokens = false;
    }

    @Data
    public static class JwtProperties {
        private String issuer = "https://authserver.company.com";
        private KeyStoreProperties keyStore = new KeyStoreProperties();
    }

    @Data
    public static class KeyStoreProperties {
        private String path = "classpath:jwt-keystore.p12";
        private String password = "changeit";
        private String alias = "jwt-key";
    }

    @Data
    public static class KeyRotationProperties {
        private boolean enabled = true;
        private int rotationDays = 90;
        private int gracePeriodDays = 7;
    }

    @Data
    public static class SecurityProperties {
        private boolean requireHttps = false;
        private boolean pkceRequiredForPublicClients = true;
        private boolean csrfProtectionEnabled = true;
    }

    @Data
    public static class RateLimitProperties {
        private boolean enabled = true;
        private int requestsPerMinute = 60;
    }

    @Data
    public static class CorsProperties {
        private List<String> allowedOrigins = List.of("https://webapp.company.com");
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE");
        private List<String> allowedHeaders = List.of("*");
        private boolean allowCredentials = true;
        private long maxAge = 3600;
    }
}
