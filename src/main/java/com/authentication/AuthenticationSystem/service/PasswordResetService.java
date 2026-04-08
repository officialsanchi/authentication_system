package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.dtos.request.ChangePasswordRequest;
import com.authentication.AuthenticationSystem.dtos.request.PasswordResetRequest;
import com.authentication.AuthenticationSystem.dtos.response.MessageResponse;
import com.authentication.AuthenticationSystem.model.PasswordResetToken;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.PasswordResetTokenRepository;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.security.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    @Transactional
    public MessageResponse requestPasswordReset(PasswordResetRequest request, HttpServletRequest httpRequest) {
        log.info("=== Password Reset Request Initiated ===");
        log.debug("Request DTO: {}", request);

        User user = userRepository.findByEmail(request.getEmail())
                .orElse(null);

        log.debug("Fetched User: {}", user);

        if (user == null) {
            log.warn("No user found with email: {}. Exiting without revealing existence.", request.getEmail());
            return MessageResponse.success("If an account exists with this email, you will receive a password reset link");
        }

        // Delete existing token
        passwordResetTokenRepository.deleteByUserId(user.getId());
        log.debug("Deleted existing password reset tokens for user: {}", user.getId());

        // Create new token
        PasswordResetToken token = PasswordResetToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .build();

        log.debug("Created PasswordResetToken: {}", token);

        passwordResetTokenRepository.save(token);
        log.info("Saved new password reset token for user: {}", user.getId());

        // Send email
        emailService.sendPasswordResetEmail(user, token.getToken());

        // Audit log
        auditLogService.log(
                user.getId(),
                "PASSWORD_RESET_REQUEST",
                "User",
                user.getId().toString(),
                "INFO",
                "Password reset requested",
                null,
                null,
                getClientIP(httpRequest),
                httpRequest.getHeader("User-Agent")
        );

        return MessageResponse.success("If an account exists with this email, you will receive a password reset link");
    }

    @Transactional
    public MessageResponse resetPassword(ChangePasswordRequest request, HttpServletRequest httpRequest) {
        log.info("=== Resetting Password ===");
        log.debug("Request DTO: {}", request);

        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Invalid or expired password reset token"));

        log.debug("Fetched PasswordResetToken: {}", resetToken);

        if (resetToken.isExpired() || resetToken.isUsed()) {
            log.warn("Token expired or already used: {}", resetToken);
            throw new RuntimeException("Password reset token has expired or already been used");
        }

        User user = resetToken.getUser();
        log.debug("Token belongs to User: {}", user);

        // Update password
        String encodedPassword = passwordEncoder.encode(request.getNewPassword());
        userRepository.updatePassword(user.getId(), encodedPassword);
        log.info("Password updated for user: {}", user.getId());

        // Mark token as used
        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);
        log.debug("Marked token as used: {}", resetToken);

        // Revoke all refresh tokens
        refreshTokenService.revokeAllUserTokens(user.getId());
        log.info("Revoked all refresh tokens for user: {}", user.getId());

        // Audit log
        auditLogService.log(
                user.getId(),
                "PASSWORD_RESET",
                "User",
                user.getId().toString(),
                "INFO",
                "Password reset successfully",
                null,
                null,
                getClientIP(httpRequest),
                httpRequest.getHeader("User-Agent")
        );

        return MessageResponse.success("Password has been reset successfully. Please login with your new password.");
    }

    @Transactional
    public MessageResponse changePassword(Long userId, String currentPassword, String newPassword,
                                          HttpServletRequest httpRequest) {
        log.info("=== Changing Password ===");
        log.debug("UserID: {}, Current Password Provided: {}, New Password: {}", userId, currentPassword, newPassword);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        log.debug("Fetched User: {}", user);

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            log.warn("Current password does not match for user: {}", userId);
            throw new RuntimeException("Current password is incorrect");
        }

        String encodedPassword = passwordEncoder.encode(newPassword);
        userRepository.updatePassword(user.getId(), encodedPassword);
        log.info("Password updated for user: {}", user.getId());

        refreshTokenService.revokeAllUserTokens(user.getId());
        log.info("Revoked all refresh tokens for user: {}", user.getId());

        auditLogService.log(
                user.getId(),
                "PASSWORD_CHANGE",
                "User",
                user.getId().toString(),
                "INFO",
                "Password changed successfully",
                null,
                null,
                getClientIP(httpRequest),
                httpRequest.getHeader("User-Agent")
        );

        return MessageResponse.success("Password changed successfully. Please login again on all devices.");
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null){
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
