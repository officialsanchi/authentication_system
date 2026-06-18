package com.authentication.AuthenticationSystem.controller;

import com.authentication.AuthenticationSystem.dtos.request.*;

import com.authentication.AuthenticationSystem.dtos.response.AuthResponse;

import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.service.AuthService;
import com.authentication.AuthenticationSystem.service.FileStorageService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final  FileStorageService fileStorageService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest req) {
        try {
            authService.registerUser(req);
            return ResponseEntity.ok(AuthResponse.of("Registration successful. Check email for OTP.", true));
        } catch (RuntimeException e) {
            // Return the actual error message (e.g., "User already exists") with a 400 status
            return ResponseEntity.badRequest().body(AuthResponse.of(e.getMessage(), false));
        }
    }
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req) {
        try {
            AuthResponse response = authService.login(req.getIdentifier(), req.getPassword());
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {

            return ResponseEntity.status(400).body(
                    AuthResponse.builder()
                            .message(e.getMessage())
                            .success(false)
                            .build()
            );
        }
    }
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest req) {
        AuthResponse response = authService.verifyOtp(req);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<AuthResponse> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        AuthResponse response = authService.resetPassword(request);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/upload-photo")
    public ResponseEntity<AuthResponse> uploadPhoto(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("file") MultipartFile file) {

        // Basic validation: Check if file is an image
        if (file.getContentType() == null || !file.getContentType().startsWith("image/")) {
            return ResponseEntity.badRequest().body(AuthResponse.of("Only image files are allowed", false));
        }

        AuthResponse response = authService.updateProfilePhoto(userDetails.getUsername(), file);
        return ResponseEntity.ok(response);
    }
    @PutMapping("/me")
    public ResponseEntity<?> updateProfile(Principal principal, @RequestBody UpdateRequest request) {
        User updated = authService.updateProfile(principal.getName(), request);
        return ResponseEntity.ok(Map.of("message", "Profile updated successfully", "user", updated));
    }


    @PostMapping("/me/password")
    public ResponseEntity<?> changePassword(Principal principal, @RequestBody PasswordChangeRequest request) {
        authService.updatePassword(principal.getName(), request);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }


    @PostMapping("/me/photo")
    public ResponseEntity<?> uploadPhoto(Principal principal, @RequestParam("file") MultipartFile file) {
        try {

            if (file.getContentType() == null || !file.getContentType().startsWith("image/")) {
                return ResponseEntity.badRequest().body(Map.of("message", "Only image files are allowed"));
            }

            User user = authService.getUserByEmail(principal.getName());

            String photoUrl = fileStorageService.saveProfilePhoto(file, user);

            return ResponseEntity.ok(Map.of(
                    "message", "Photo uploaded successfully",
                    "photoUrl", photoUrl
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", "Upload failed: " + e.getMessage()));
        }
    }

    @DeleteMapping("/me")
    public ResponseEntity<?> deleteAccount(Principal principal) {
        authService.deleteUser(principal.getName());
        return ResponseEntity.ok(Map.of("message", "Account deleted successfully"));
    }


}
