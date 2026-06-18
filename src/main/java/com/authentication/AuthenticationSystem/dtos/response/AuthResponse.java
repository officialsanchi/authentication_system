package com.authentication.AuthenticationSystem.dtos.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
@Data
@AllArgsConstructor
@Builder
public class AuthResponse {
    private String message;
    private boolean success;
    private String token;
    private String username;
    private String profilePhotoUrl;
    public static AuthResponse of(String message, boolean success) {
        return AuthResponse.builder()
                .message(message)
                .success(success)
                .build();
    }
}
