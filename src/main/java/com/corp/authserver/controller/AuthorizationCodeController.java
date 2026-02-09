package com.corp.authserver.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthorizationCodeController {

    private static final String TOKEN_ENDPOINT = "http://localhost:9000/oauth2/token";

    @PostMapping("/token")
    public ResponseEntity<?> exchangeAuthorizationCode(@RequestBody Map<String, String> request) {
        String code = request.get("code");
        String codeVerifier = request.get("code_verifier");
        String redirectUri = request.get("redirect_uri");
        String clientId = request.get("client_id");

        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "authorization_code is required"));
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "redirect_uri is required"));
        }
        if (clientId == null || clientId.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "client_id is required"));
        }

        log.debug("Exchanging authorization code for client_id={}, redirect_uri={}", clientId, redirectUri);

        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "authorization_code");
            params.add("code", code);
            params.add("redirect_uri", redirectUri);
            params.add("client_id", clientId);

            if (codeVerifier != null && !codeVerifier.isBlank()) {
                params.add("code_verifier", codeVerifier);
            }

            HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(params, headers);

            ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                    TOKEN_ENDPOINT,
                    HttpMethod.POST,
                    tokenRequest,
                    Map.class
            );

            log.debug("Token exchange successful for client_id={}", clientId);
            return ResponseEntity.ok(tokenResponse.getBody());

        } catch (Exception ex) {
            log.error("Token exchange failed for client_id={}: {}", clientId, ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "token_exchange_failed", "message", ex.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refresh_token");
        String clientId = request.get("client_id");

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "refresh_token is required"));
        }
        if (clientId == null || clientId.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "client_id is required"));
        }

        log.debug("Refreshing token for client_id={}", clientId);

        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "refresh_token");
            params.add("refresh_token", refreshToken);
            params.add("client_id", clientId);

            HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(params, headers);

            ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                    TOKEN_ENDPOINT,
                    HttpMethod.POST,
                    tokenRequest,
                    Map.class
            );

            log.debug("Token refresh successful for client_id={}", clientId);
            return ResponseEntity.ok(tokenResponse.getBody());

        } catch (Exception ex) {
            log.error("Token refresh failed for client_id={}: {}", clientId, ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "token_refresh_failed", "message", ex.getMessage()));
        }
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> revokeToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String clientId = request.get("client_id");

        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "token is required"));
        }

        log.debug("Revoking token for client_id={}", clientId);

        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("token", token);
            if (clientId != null && !clientId.isBlank()) {
                params.add("client_id", clientId);
            }

            HttpEntity<MultiValueMap<String, String>> revokeRequest = new HttpEntity<>(params, headers);

            restTemplate.exchange(
                    "http://localhost:9000/oauth2/revoke",
                    HttpMethod.POST,
                    revokeRequest,
                    Void.class
            );

            log.debug("Token revocation successful");
            return ResponseEntity.ok(Map.of("status", "token_revoked"));

        } catch (Exception ex) {
            log.error("Token revocation failed: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "token_revocation_failed", "message", ex.getMessage()));
        }
    }
}
