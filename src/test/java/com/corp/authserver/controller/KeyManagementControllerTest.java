package com.corp.authserver.controller;

import com.corp.authserver.service.KeyRotationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class KeyManagementControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeyRotationService keyRotationService;

    @Test
    @DisplayName("FR-KEY-02: Should rotate keys via API")
    @WithMockUser(roles = "ADMIN")
    void shouldRotateKeys() throws Exception {
        when(keyRotationService.getCurrentKeyId()).thenReturn("new-key-id");
        when(keyRotationService.getActiveKeyCount()).thenReturn(2);

        mockMvc.perform(post("/api/keys/rotate").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("rotated"))
                .andExpect(jsonPath("$.activeKeyId").value("new-key-id"))
                .andExpect(jsonPath("$.totalKeys").value(2));

        verify(keyRotationService).rotateKeys();
    }

    @Test
    @DisplayName("Should return key status")
    @WithMockUser(roles = "ADMIN")
    void shouldReturnKeyStatus() throws Exception {
        when(keyRotationService.getCurrentKeyId()).thenReturn("current-key-id");
        when(keyRotationService.getActiveKeyCount()).thenReturn(1);

        mockMvc.perform(get("/api/keys/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeKeyId").value("current-key-id"))
                .andExpect(jsonPath("$.totalKeys").value(1));
    }

    @Test
    @DisplayName("Should reject unauthenticated key rotation")
    void shouldRejectUnauthenticatedKeyRotation() throws Exception {
        mockMvc.perform(post("/api/keys/rotate"))
                .andExpect(status().isForbidden());
    }
}
