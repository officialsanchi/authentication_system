package com.authentication.AuthenticationSystem.service;


import com.authentication.AuthenticationSystem.dtos.request.*;
import com.authentication.AuthenticationSystem.dtos.response.AuthResponse;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import com.authentication.AuthenticationSystem.security.JwtUtils;
import com.cloudinary.Cloudinary;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final CloudinaryService cloudinaryService;
    private final JwtUtils jwtUtils;

    @Transactional
    public void registerUser(RegisterRequest request) {
        String normalizedEmail = request.getEmail().trim().toLowerCase();
        String normalizedUsername = request.getUsername().trim();

        if (userRepository.findByAnyIdentifier(normalizedEmail).isPresent() ||
                userRepository.findByAnyIdentifier(normalizedUsername).isPresent()) {
            throw new RuntimeException("User already exists with this email or username");
        }

        User user = User.builder()
                .fullName(request.getFullName().trim())
                .username(normalizedUsername)
                .email(normalizedEmail)
                .phoneNumber(request.getPhoneNumber() != null ? request.getPhoneNumber().trim() : null)
                .password(passwordEncoder.encode(request.getPassword().trim()))
                .enabled(false)
                .build();

        userRepository.save(user);

        otpService.generateAndSendOtp(user, "Verify Your Registration");
    }

    @Transactional
    public void forgotPassword(String email) {
        String normalizedEmail = email.trim().toLowerCase();

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new RuntimeException("No account found with this email"));

        otpService.generateAndSendOtp(
                user,
                "Password Reset Verification"
        );
    }
    public AuthResponse login(String identifier, String rawPassword) {
        String normalizedIdentifier = identifier.trim().toLowerCase();
        String cleanPassword = rawPassword.trim();

        System.out.println("=================== LOGIN DEBUG ===================");
        System.out.println("Identifier received: [" + normalizedIdentifier + "]");

        User user = userRepository.findByAnyIdentifier(normalizedIdentifier)
                .orElseThrow(() -> {
                    System.out.println("DEBUG RESULT: USER NOT FOUND IN DATABASE!");
                    return new RuntimeException("Invalid credentials");
                });

        System.out.println("User found: Email=" + user.getEmail() + " | Username=" + user.getUsername());
        System.out.println("Stored Encoded Password: " + user.getPassword());

        boolean matches = passwordEncoder.matches(cleanPassword, user.getPassword());
        System.out.println("BCrypt Matches?: " + matches);
        System.out.println("User Enabled Status: " + user.isEnabled());
        System.out.println("===================================================");

        if (!matches) {
            throw new RuntimeException("Invalid credentials");
        }

        if (!user.isEnabled()) {
            throw new RuntimeException("Please verify your account via OTP first");
        }

        String token = jwtUtils.generateToken(user.getEmail());

        return AuthResponse.builder()
                .message("Login successful")
                .success(true)
                .token(token)
                .username(user.getUsername())
                .profilePhotoUrl(user.getProfilePhotoUrl())
                .build();
    }

    @Transactional
    public AuthResponse verifyResetOtp(VerifyOtpRequest request) {
        String email = request.getEmail().trim().toLowerCase();
        String otp = request.getOtp().trim();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!otpService.isOtpValid(user, otp)) {
            throw new RuntimeException("Invalid or expired OTP");
        }

        // Auto-enable user if verifying registration or reset
        if (!user.isEnabled()) {
            user.setEnabled(true);
            userRepository.save(user);
        }

        return AuthResponse.of(
                "OTP verified successfully.",
                true
        );
    }

    @Transactional
    public AuthResponse resetPassword(PasswordResetRequest request) {
        String email = request.getEmail().trim().toLowerCase();
        String otp = request.getOtp().trim();
        String rawNewPassword = request.getNewPassword().trim(); // Clean raw password

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getOtpCode() == null || !user.getOtpCode().equals(otp)) {
            throw new RuntimeException("Invalid OTP");
        }

        if (user.getOtpExpiry() == null || user.getOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("OTP expired");
        }

        // 1. Encode raw password using BCrypt
        String encodedPassword = passwordEncoder.encode(rawNewPassword);

        System.out.println("=== RESET PASSWORD DEBUG ===");
        System.out.println("Raw new password: [" + rawNewPassword + "]");
        System.out.println("Generated Hash: [" + encodedPassword + "]");
        System.out.println("============================");

        user.setPassword(encodedPassword);
        user.setEnabled(true);

        // Clear OTP
        user.setOtpCode(null);
        user.setOtpExpiry(null);

        userRepository.save(user);

        return AuthResponse.of("Password reset successful!", true);
    }

    @Transactional
    public String updateProfilePhoto(MultipartFile file, String email) {
        String normalizedEmail = email.trim().toLowerCase();

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String imageUrl = cloudinaryService.uploadProfilePhoto(file);
        user.setProfilePhotoUrl(imageUrl);
        userRepository.save(user);

        return imageUrl;
    }

    public User getUserByEmail(String email) {
        String normalizedEmail = email.trim().toLowerCase();
        return userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
    }

    @Transactional
    public void updatePassword(String email, PasswordChangeRequest request) {
        String normalizedEmail = email.trim().toLowerCase();

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getOldPassword().trim(), user.getPassword())) {
            throw new RuntimeException("Current password does not match");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword().trim()));
        userRepository.save(user);
    }

    @Transactional
    public void deleteUser(String email) {
        String normalizedEmail = email.trim().toLowerCase();
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userRepository.delete(user);
    }

}
