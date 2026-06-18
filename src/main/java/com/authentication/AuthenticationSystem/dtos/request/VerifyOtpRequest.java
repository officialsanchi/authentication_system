package com.authentication.AuthenticationSystem.dtos.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class VerifyOtpRequest {
    @Email
    @NotBlank String email;
    @NotBlank
    String otp;
}
