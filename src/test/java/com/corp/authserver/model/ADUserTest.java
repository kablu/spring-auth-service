package com.corp.authserver.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ADUserTest {

    @Test
    @DisplayName("Should map roles to Spring Security authorities with ROLE_ prefix")
    void shouldMapRolesToAuthorities() {
        ADUser user = ADUser.builder()
                .username("testuser")
                .roles(List.of("USER", "ADMIN"))
                .enabled(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();

        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

        assertThat(authorities).hasSize(2);
        assertThat(authorities).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("Should return displayName as fullName when available")
    void shouldReturnDisplayNameAsFullName() {
        ADUser user = ADUser.builder()
                .username("jdoe")
                .displayName("John Doe")
                .roles(List.of())
                .build();

        assertThat(user.getFullName()).isEqualTo("John Doe");
    }

    @Test
    @DisplayName("Should return username as fullName when displayName is null")
    void shouldReturnUsernameWhenNoDisplayName() {
        ADUser user = ADUser.builder()
                .username("jdoe")
                .roles(List.of())
                .build();

        assertThat(user.getFullName()).isEqualTo("jdoe");
    }

    @Test
    @DisplayName("Should check role membership")
    void shouldCheckRoleMembership() {
        ADUser user = ADUser.builder()
                .username("testuser")
                .roles(List.of("USER", "ADMIN"))
                .build();

        assertThat(user.hasRole("USER")).isTrue();
        assertThat(user.hasRole("ADMIN")).isTrue();
        assertThat(user.hasRole("SUPERADMIN")).isFalse();
    }

    @Test
    @DisplayName("Should implement UserDetails interface correctly")
    void shouldImplementUserDetails() {
        ADUser user = ADUser.builder()
                .username("testuser")
                .password("secret")
                .enabled(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .roles(List.of("USER"))
                .build();

        assertThat(user.getUsername()).isEqualTo("testuser");
        assertThat(user.getPassword()).isEqualTo("secret");
        assertThat(user.isEnabled()).isTrue();
        assertThat(user.isAccountNonExpired()).isTrue();
        assertThat(user.isCredentialsNonExpired()).isTrue();
        assertThat(user.isAccountNonLocked()).isTrue();
    }
}
