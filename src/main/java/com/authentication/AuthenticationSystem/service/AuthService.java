package com.authentication.AuthenticationSystem.service;


import com.authentication.AuthenticationSystem.dtos.request.*;
import com.authentication.AuthenticationSystem.dtos.response.AuthResponse;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import com.authentication.AuthenticationSystem.security.JwtUtils;
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
    private final FileStorageService fileStorageService;
    private final JwtUtils jwtUtils;

    @Transactional
    public void registerUser(RegisterRequest request) {
        if (userRepository.findByAnyIdentifier(request.getEmail()).isPresent()) {
            throw new RuntimeException("User already exists");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .phoneNumber(request.getPhoneNumber())
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(false)
                .build();

        userRepository.save(user);

        // DRY CALL
        otpService.generateAndSendOtp(user, "Verify Your Registration");
    }

    public AuthResponse login(String identifier, String password) {
        User user = userRepository.findByAnyIdentifier(identifier)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        if (!user.isEnabled()) {
            throw new RuntimeException("Please verify your account via OTP first");
        }

        String token = jwtUtils.generateToken(user.getUsername());

        return AuthResponse.builder()
                .message("Login successful")
                .success(true)
                .token(token)
                .username(user.getUsername())
                .profilePhotoUrl(user.getProfilePhotoUrl())
                .build();
    }

    @Transactional
    public AuthResponse verifyOtp(VerifyOtpRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!otpService.isOtpValid(user, request.getOtp())) {
            throw new RuntimeException("Invalid or expired OTP");
        }

        user.setEnabled(true);
        otpService.clearOtp(user); // Clean up DB

        return AuthResponse.of("Account verified!", true);
    }



    public AuthResponse updateProfilePhoto(String username, MultipartFile file) {
        User user = userRepository.findByAnyIdentifier(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 1. Save file to disk
        String filename = fileStorageService.saveProfilePhoto(file, user);

        // 2. Update database with the path/URL
        user.setProfilePhotoUrl("/uploads/profile-photos/" + filename);
        userRepository.save(user);

        return AuthResponse.of("Profile photo updated successfully", true);
    }
    @Transactional
    public AuthResponse resetPassword(PasswordResetRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 1. Validate
        if (user.getOtpCode() == null || !user.getOtpCode().equals(request.getOtp())) {
            throw new RuntimeException("Invalid OTP");
        }

        if (user.getOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("OTP expired");
        }

        // 2. Change Password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // TIGHTEN LOGIC: Wipe the code immediately
        user.setOtpCode(null);
        user.setOtpExpiry(null);

        userRepository.save(user);
        return AuthResponse.of("Password reset successful!", true);
    }
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
    }

    private String generateOTP() {
        // SecureRandom is better for real-life security than Random
        return String.format("%06d", new SecureRandom().nextInt(999999));
    }
    public User updateProfile(String email, UpdateRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setUsername(request.getUsername());
        user.setPhoneNumber(request.getPhoneNumber());
        return userRepository.save(user);
    }

    public void updatePassword(String email, PasswordChangeRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Verify old password
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Current password does not match");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    public void deleteUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userRepository.delete(user);
    }


}
