package com.authentication.AuthenticationSystem.dtos.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@Builder
public class UserResponse {
    private Long id;
    private String username;
    private String phoneNumber;
    private String firstName;
    private String lastName;
    private String email;
    private Set<String> roles;
    private boolean emailVerified;
    private boolean enabled;
    private boolean accountNonLocked;
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;
}
