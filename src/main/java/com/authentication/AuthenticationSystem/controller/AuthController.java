package com.authentication.AuthenticationSystem.controller;

import com.authentication.AuthenticationSystem.dtos.request.LoginRequest;
import com.authentication.AuthenticationSystem.dtos.request.RefreshTokenRequest;
import com.authentication.AuthenticationSystem.dtos.request.RegisterRequest;
import com.authentication.AuthenticationSystem.dtos.request.VerifyEmailRequest;
import com.authentication.AuthenticationSystem.dtos.response.JwtResponse;
import com.authentication.AuthenticationSystem.dtos.response.MessageResponse;
import com.authentication.AuthenticationSystem.dtos.response.UserResponse;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import com.authentication.AuthenticationSystem.security.UserDetailsImpl;
import com.authentication.AuthenticationSystem.service.AuthService;
import com.authentication.AuthenticationSystem.service.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final PasswordResetService passwordResetService;

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {
        return ResponseEntity.ok(authService.authenticateUser(loginRequest, request));
    }

    @PostMapping("/register")
    public ResponseEntity<MessageResponse> registerUser(
            @Valid @RequestBody RegisterRequest registerRequest,
            HttpServletRequest request) {
        return ResponseEntity.ok(authService.registerUser(registerRequest, request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest refreshTokenRequest,
            HttpServletRequest request) {
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest.getRefreshToken(), request));
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest,
            HttpServletRequest request) {

        String accessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }

        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.getRefreshToken() : null;

        return ResponseEntity.ok(authService.logout(accessToken, refreshToken, request));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<MessageResponse> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        // Implementation in EmailVerificationService
        return ResponseEntity.ok(MessageResponse.success("Email verified successfully"));
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        User user = userRepository.findById(userDetails.getId()).orElseThrow();

        return ResponseEntity.ok(UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream().map(Enum::name).collect(java.util.stream.Collectors.toSet()))
                .emailVerified(user.isEmailVerified())
                .enabled(user.isEnabled())
                .accountNonLocked(user.isAccountNonLocked())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .build());
    }
}
