package com.corp.authserver.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

@Slf4j
@Service
public class CustomOidcUserInfoService {

    private static final Map<String, Map<String, Object>> USER_PROFILES = Map.of(
            "user", Map.ofEntries(
                    Map.entry("sub", "user"),
                    Map.entry("preferred_username", "user"),
                    Map.entry("name", "John Doe"),
                    Map.entry("given_name", "John"),
                    Map.entry("family_name", "Doe"),
                    Map.entry("email", "john.doe@company.com"),
                    Map.entry("email_verified", true),
                    Map.entry("phone_number", "+1-555-0101"),
                    Map.entry("address", Map.of(
                            "street_address", "123 Main Street",
                            "locality", "Springfield",
                            "region", "IL",
                            "postal_code", "62701",
                            "country", "US"
                    )),
                    Map.entry("picture", "https://i.pravatar.cc/150?u=user"),
                    Map.entry("locale", "en-US"),
                    Map.entry("zoneinfo", "America/Chicago"),
                    Map.entry("department", "Engineering"),
                    Map.entry("employee_id", "EMP-1001"),
                    Map.entry("title", "Software Engineer"),
                    Map.entry("roles", Set.of("ROLE_USER"))
            ),
            "admin", Map.ofEntries(
                    Map.entry("sub", "admin"),
                    Map.entry("preferred_username", "admin"),
                    Map.entry("name", "Jane Admin"),
                    Map.entry("given_name", "Jane"),
                    Map.entry("family_name", "Admin"),
                    Map.entry("email", "jane.admin@company.com"),
                    Map.entry("email_verified", true),
                    Map.entry("phone_number", "+1-555-0200"),
                    Map.entry("address", Map.of(
                            "street_address", "456 Corporate Blvd",
                            "locality", "Springfield",
                            "region", "IL",
                            "postal_code", "62702",
                            "country", "US"
                    )),
                    Map.entry("picture", "https://i.pravatar.cc/150?u=admin"),
                    Map.entry("locale", "en-US"),
                    Map.entry("zoneinfo", "America/Chicago"),
                    Map.entry("department", "IT Administration"),
                    Map.entry("employee_id", "EMP-0001"),
                    Map.entry("title", "System Administrator"),
                    Map.entry("roles", Set.of("ROLE_USER", "ROLE_ADMIN"))
            )
    );

    public OidcUserInfo loadUser(String username, Set<String> scopes) {
        log.debug("Loading user info for: {} with scopes: {}", username, scopes);

        Map<String, Object> profile = USER_PROFILES.get(username);
        if (profile == null) {
            log.warn("No profile found for user: {}, returning minimal info", username);
            return OidcUserInfo.builder()
                    .subject(username)
                    .preferredUsername(username)
                    .build();
        }

        OidcUserInfo.Builder builder = OidcUserInfo.builder()
                .subject(username);

        // openid scope - always included
        builder.preferredUsername((String) profile.get("preferred_username"));

        // profile scope
        if (scopes.contains("profile")) {
            builder.name((String) profile.get("name"))
                    .givenName((String) profile.get("given_name"))
                    .familyName((String) profile.get("family_name"))
                    .picture((String) profile.get("picture"))
                    .locale((String) profile.get("locale"))
                    .zoneinfo((String) profile.get("zoneinfo"))
                    .claim("department", profile.get("department"))
                    .claim("employee_id", profile.get("employee_id"))
                    .claim("title", profile.get("title"))
                    .claim("roles", profile.get("roles"));
        }

        // email scope
        if (scopes.contains("email")) {
            builder.email((String) profile.get("email"))
                    .emailVerified((Boolean) profile.get("email_verified"));
        }

        // phone scope
        if (scopes.contains("phone")) {
            builder.phoneNumber((String) profile.get("phone_number"));
        }

        // address scope
        if (scopes.contains("address")) {
            builder.address(profile.get("address").toString());
        }

        OidcUserInfo userInfo = builder.build();
        log.debug("Returning user info with {} claims for user: {}", userInfo.getClaims().size(), username);
        return userInfo;
    }
}
