package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
@Service
@RequiredArgsConstructor
public class OtpService {
    private final UserRepository userRepository;
    private final EmailService emailService;

    private final SecureRandom secureRandom = new SecureRandom();

    // ==========================================
    // GENERATE AND SEND OTP
    // ==========================================

    public void generateAndSendOtp(User user, String subject) {

        // Generate a 6-digit OTP
        String otp = String.format(
                "%06d",
                secureRandom.nextInt(1_000_000)
        );

        // OTP expires after 10 minutes
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(10);

        // Store OTP
        user.setOtpCode(otp);
        user.setOtpExpiry(expiry);

        // Save OTP and expiry to database
        userRepository.save(user);

        // Debug information
        System.out.println("=================================");
        System.out.println("OTP GENERATED");
        System.out.println("Email: " + user.getEmail());
        System.out.println("OTP: " + otp);
        System.out.println("Expiry: " + expiry);
        System.out.println("=================================");

        // Send the SAME OTP that was saved
        emailService.sendOtpEmail(
                user.getEmail(),
                otp,
                subject
        );
    }

    // ==========================================
    // VERIFY OTP
    // ==========================================

    public boolean isOtpValid(User user, String inputOtp) {

        String storedOtp = user.getOtpCode();
        LocalDateTime storedExpiry = user.getOtpExpiry();

        LocalDateTime now = LocalDateTime.now();

        System.out.println("==========================================");
        System.out.println("OTP VALIDATION");
        System.out.println("Email: " + user.getEmail());
        System.out.println("Stored OTP: " + storedOtp);
        System.out.println("Input OTP: " + inputOtp);
        System.out.println("Stored Expiry: " + storedExpiry);
        System.out.println("Current Time: " + now);

        boolean otpMatches =
                storedOtp != null &&
                        inputOtp != null &&
                        storedOtp.equals(inputOtp.trim());

        boolean notExpired =
                storedExpiry != null &&
                        storedExpiry.isAfter(now);

        System.out.println("OTP Matches: " + otpMatches);
        System.out.println("OTP Not Expired: " + notExpired);
        System.out.println("OTP VALID: " + (otpMatches && notExpired));
        System.out.println("==========================================");

        return otpMatches && notExpired;
    }
    public void clearOtp(User user) {

        user.setOtpCode(null);
        user.setOtpExpiry(null);

        userRepository.save(user);

        System.out.println(
                "OTP cleared for: " + user.getEmail()
        );
    }

}
