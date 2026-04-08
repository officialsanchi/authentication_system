package com.authentication.AuthenticationSystem.dtos.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;
    @NotBlank(message = "phoneNumber is required")
    private String phoneNumber;
    @NotBlank(message = "email is required")
    private String email;
}
