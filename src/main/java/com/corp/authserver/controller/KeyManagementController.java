package com.corp.authserver.controller;

import com.corp.authserver.service.KeyRotationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/keys")
@RequiredArgsConstructor
public class KeyManagementController {

    private final KeyRotationService keyRotationService;

    @PostMapping("/rotate")
    public ResponseEntity<Map<String, Object>> rotateKeys() {
        keyRotationService.rotateKeys();
        return ResponseEntity.ok(Map.of(
                "status", "rotated",
                "activeKeyId", keyRotationService.getCurrentKeyId(),
                "totalKeys", keyRotationService.getActiveKeyCount()
        ));
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getKeyStatus() {
        return ResponseEntity.ok(Map.of(
                "activeKeyId", keyRotationService.getCurrentKeyId(),
                "totalKeys", keyRotationService.getActiveKeyCount()
        ));
    }
}
