package com.corp.authserver.controller;

import com.corp.authserver.dto.ClientRegistrationRequest;
import com.corp.authserver.dto.ClientResponse;
import com.corp.authserver.service.ClientManagementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/clients")
@RequiredArgsConstructor
public class ClientManagementController {

    private final ClientManagementService clientManagementService;

    @PostMapping
    public ResponseEntity<ClientResponse> registerClient(
            @Valid @RequestBody ClientRegistrationRequest request) {
        ClientResponse response = clientManagementService.registerClient(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<ClientResponse> getClient(@PathVariable String clientId) {
        ClientResponse response = clientManagementService.getClient(clientId);
        return ResponseEntity.ok(response);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", ex.getMessage()));
    }
}
