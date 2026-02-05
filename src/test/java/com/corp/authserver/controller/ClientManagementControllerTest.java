package com.corp.authserver.controller;

import com.corp.authserver.dto.ClientRegistrationRequest;
import com.corp.authserver.dto.ClientResponse;
import com.corp.authserver.service.ClientManagementService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ClientManagementControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private ClientManagementService clientManagementService;

    @Test
    @DisplayName("FR-CLIENT-01: Should register new client via API")
    @WithMockUser(roles = "ADMIN")
    void shouldRegisterNewClient() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("new-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        ClientResponse response = ClientResponse.builder()
                .id("generated-id")
                .clientId("new-client")
                .clientIdIssuedAt(Instant.now())
                .clientAuthenticationMethods(Set.of("client_secret_basic"))
                .authorizationGrantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .accessTokenTtlSeconds(3600L)
                .build();

        when(clientManagementService.registerClient(any())).thenReturn(response);

        mockMvc.perform(post("/api/clients")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.clientId").value("new-client"))
                .andExpect(jsonPath("$.authorizationGrantTypes[0]").value("client_credentials"));
    }

    @Test
    @DisplayName("Should return 401 for unauthenticated client registration")
    void shouldRejectUnauthenticatedRegistration() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("new-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("client_credentials"))
                .scopes(Set.of("read"))
                .build();

        mockMvc.perform(post("/api/clients")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should retrieve client by clientId")
    @WithMockUser(roles = "ADMIN")
    void shouldRetrieveClient() throws Exception {
        ClientResponse response = ClientResponse.builder()
                .id("test-id")
                .clientId("web-client")
                .clientAuthenticationMethods(Set.of("client_secret_basic"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .scopes(Set.of("openid", "profile"))
                .accessTokenTtlSeconds(3600L)
                .build();

        when(clientManagementService.getClient("web-client")).thenReturn(response);

        mockMvc.perform(get("/api/clients/web-client"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value("web-client"));
    }

    @Test
    @DisplayName("Should return 400 for invalid client request")
    @WithMockUser(roles = "ADMIN")
    void shouldReturn400ForInvalidRequest() throws Exception {
        when(clientManagementService.registerClient(any()))
                .thenThrow(new IllegalArgumentException("Deprecated grant type not supported: password"));

        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientId("bad-client")
                .clientSecret("secret")
                .authenticationMethods(Set.of("client_secret_basic"))
                .grantTypes(Set.of("password"))
                .scopes(Set.of("read"))
                .build();

        mockMvc.perform(post("/api/clients")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Deprecated grant type not supported: password"));
    }
}
