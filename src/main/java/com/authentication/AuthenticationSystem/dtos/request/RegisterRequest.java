package com.authentication.AuthenticationSystem.dtos.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

@Data
public class RegisterRequest {
    @NotBlank(message = "Username is required")
    @JsonProperty("username")
    private String username;

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    @JsonProperty("email")
    private String email;

    @NotBlank(message = "Phone number is required")
    @JsonProperty("phoneNumber")
    private String phoneNumber;

    @Size(min = 8, message = "Password must be at least 8 characters")
    @JsonProperty("password")
    private String password;
}
