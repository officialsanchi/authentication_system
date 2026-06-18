package com.authentication.AuthenticationSystem.dtos.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @JsonProperty("identifier") // Explicitly map the JSON key
    @NotBlank(message = "Identifier is required")
    private String identifier;

    @JsonProperty("password")
    @NotBlank(message = "Password is required")
    private String password;
}
