package com.corp.authserver.service;

import com.corp.authserver.config.AuthServerProperties;
import com.corp.authserver.config.JwkConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeyRotationService {

    private final JwkConfig jwkConfig;
    private final AuthServerProperties properties;

    @Scheduled(cron = "0 0 2 * * ?") // Run daily at 2 AM
    public void checkAndRotateKeys() {
        if (!properties.getKeyRotation().isEnabled()) {
            return;
        }

        String currentKeyId = jwkConfig.getCurrentKeyId();
        Instant keyCreation = jwkConfig.getKeyCreationTime(currentKeyId);
        Duration keyAge = Duration.between(keyCreation, Instant.now());
        long rotationDays = properties.getKeyRotation().getRotationDays();

        if (keyAge.toDays() >= rotationDays) {
            log.info("Key {} is {} days old (threshold: {}). Rotating...", currentKeyId, keyAge.toDays(), rotationDays);
            rotateKeys();
        } else {
            log.debug("Key {} is {} days old. No rotation needed (threshold: {} days).", currentKeyId, keyAge.toDays(), rotationDays);
        }

        cleanupExpiredKeys();
    }

    public void rotateKeys() {
        jwkConfig.rotateKey();
        log.info("Key rotation completed. New active key: {}", jwkConfig.getCurrentKeyId());
    }

    public void cleanupExpiredKeys() {
        int gracePeriodDays = properties.getKeyRotation().getGracePeriodDays();
        String currentKeyId = jwkConfig.getCurrentKeyId();
        List<String> keysToRemove = new ArrayList<>();

        jwkConfig.getKeyMap().forEach((keyId, rsaKey) -> {
            if (!keyId.equals(currentKeyId)) {
                Instant keyCreation = jwkConfig.getKeyCreationTime(keyId);
                Duration keyAge = Duration.between(keyCreation, Instant.now());
                if (keyAge.toDays() > properties.getKeyRotation().getRotationDays() + gracePeriodDays) {
                    keysToRemove.add(keyId);
                }
            }
        });

        keysToRemove.forEach(keyId -> {
            jwkConfig.removeKey(keyId);
            log.info("Removed expired key: {}", keyId);
        });
    }

    public int getActiveKeyCount() {
        return jwkConfig.getKeyMap().size();
    }

    public String getCurrentKeyId() {
        return jwkConfig.getCurrentKeyId();
    }
}
