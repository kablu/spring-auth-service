package com.corp.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nimbusds.jose.jwk.JWK;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Configuration
public class JwkConfig {

    private final Map<String, RSAKey> keyMap = new ConcurrentHashMap<>();
    private volatile String currentKeyId;

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsaKey();
        currentKeyId = rsaKey.getKeyID();
        keyMap.put(currentKeyId, rsaKey);
        log.info("Generated initial RSA key pair with kid: {}", currentKeyId);

        return (jwkSelector, securityContext) -> {
            List<JWK> keys = new ArrayList<>(keyMap.values());
            JWKSet jwkSet = new JWKSet(keys);
            return jwkSelector.select(jwkSet);
        };
    }

    public RSAKey generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            String keyId = UUID.randomUUID().toString();
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .issueTime(new java.util.Date())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate RSA key pair", e);
        }
    }

    public void rotateKey() {
        RSAKey newKey = generateRsaKey();
        String newKeyId = newKey.getKeyID();
        keyMap.put(newKeyId, newKey);
        log.info("Rotated RSA key. New kid: {}, total keys: {}", newKeyId, keyMap.size());
        currentKeyId = newKeyId;
    }

    public void removeKey(String keyId) {
        if (!keyId.equals(currentKeyId)) {
            keyMap.remove(keyId);
            log.info("Removed expired key: {}", keyId);
        }
    }

    public String getCurrentKeyId() {
        return currentKeyId;
    }

    public Map<String, RSAKey> getKeyMap() {
        return keyMap;
    }

    public Instant getKeyCreationTime(String keyId) {
        RSAKey key = keyMap.get(keyId);
        if (key != null && key.getIssueTime() != null) {
            return key.getIssueTime().toInstant();
        }
        return Instant.now();
    }
}
