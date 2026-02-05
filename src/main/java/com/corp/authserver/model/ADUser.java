package com.corp.authserver.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Active Directory User representation
 * Implements Spring Security's UserDetails for authentication
 *
 * Maps AD user attributes to application user model
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ADUser implements UserDetails {

    private String username;          // sAMAccountName or userPrincipalName
    private String password;          // Not stored, only used during authentication
    private String email;             // mail
    private String displayName;       // displayName
    private String department;        // department
    private String employeeId;        // employeeID
    private String telephoneNumber;   // telephoneNumber
    private String distinguishedName; // distinguishedName
    private List<String> roles;       // Extracted from memberOf groups
    private boolean enabled;
    private boolean accountNonExpired;
    private boolean credentialsNonExpired;
    private boolean accountNonLocked;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Get user's full name for display purposes
     */
    public String getFullName() {
        return displayName != null ? displayName : username;
    }

    /**
     * Check if user has a specific role
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }
}
