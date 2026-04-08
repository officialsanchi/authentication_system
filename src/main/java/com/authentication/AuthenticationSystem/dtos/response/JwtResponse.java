package com.authentication.AuthenticationSystem.dtos.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {
    private String accessToken;
    private String refreshToken;
    private String type;
    private Long id;
    private String username;
    private String email;
    private List<String> roles;
    private boolean emailVerified;
    private Long expiresIn;
}
