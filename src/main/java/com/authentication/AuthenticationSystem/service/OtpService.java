package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class OtpService {
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final SecureRandom secureRandom = new SecureRandom(); // More secure than Random

    public void generateAndSendOtp(User user, String subject) {
        // 1. Generate 6-digit code
        String otp = String.format("%06d", secureRandom.nextInt(999999));

        // 2. Set OTP and Expiry
        user.setOtpCode(otp); // FIXED: Added setter
        user.setOtpExpiry(LocalDateTime.now().plusMinutes(10));
        userRepository.save(user);

        // 3. Send the Email
        emailService.sendOtpEmail(user.getEmail(), otp, subject);
    }

    public boolean isOtpValid(User user, String inputOtp) {
        return user.getOtpCode() != null &&
                user.getOtpCode().equals(inputOtp) &&
                user.getOtpExpiry() != null &&
                user.getOtpExpiry().isAfter(LocalDateTime.now());
    }

    public void clearOtp(User user) {
        user.setOtpCode(null);
        user.setOtpExpiry(null);
        userRepository.save(user);
    }
}
