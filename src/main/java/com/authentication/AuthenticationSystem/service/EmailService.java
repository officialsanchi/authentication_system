package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.model.VerificationToken;
import com.authentication.AuthenticationSystem.repository.VerificationTokenRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;


import org.thymeleaf.context.Context;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    private final VerificationTokenRepository verificationTokenRepository;

    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    @Async("mailTaskExecutor")
    public void sendVerificationEmail(User user) {
        try {
            log.info("=== Starting verification email process ===");
            log.debug("User object received: {}", user);

            // Delete existing token
            verificationTokenRepository.findByUserId(user.getId())
                    .ifPresent(existing -> {
                        log.debug("Existing token found for user {}: {}", user.getId(), existing);
                        verificationTokenRepository.delete(existing);
                        log.info("Existing verification token deleted");
                    });

            // Create new token
            VerificationToken token = VerificationToken.builder()
                    .token(UUID.randomUUID().toString())
                    .user(user)
                    .build();

            log.debug("New verification token created: {}", token);

            verificationTokenRepository.save(token);
            log.info("Verification token saved: {}", token.getToken());

            // Prepare email content
            Context context = new Context();
            context.setVariable("username", user.getUsername());
            context.setVariable("verificationLink", frontendUrl + "/verify-email?token=" + token.getToken());

            log.debug("Email template context: username={}, link={}",
                    user.getUsername(), frontendUrl + "/verify-email?token=" + token.getToken());

            String htmlContent = templateEngine.process("email-verification", context);
            log.debug("Generated HTML content length: {}", htmlContent.length());

            // Create and send email
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(user.getEmail());
            helper.setSubject("Verify Your Email Address");
            helper.setText(htmlContent, true);

            log.info("Sending verification email to {}", user.getEmail());
            mailSender.send(message);

            log.info("Verification email sent successfully to: {}", user.getEmail());

        } catch (MessagingException e) {
            log.error("Failed to send verification email to: {}", user.getEmail(), e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    @Async("mailTaskExecutor")
    public void sendPasswordResetEmail(User user, String resetToken) {
        try {
            log.info("=== Starting password reset email process ===");
            log.debug("User object received: {}", user);
            log.debug("Reset token received: {}", resetToken);

            Context context = new Context();
            context.setVariable("username", user.getUsername());
            context.setVariable("resetLink", frontendUrl + "/reset-password?token=" + resetToken);

            log.debug("Email template context for reset: username={}, link={}",
                    user.getUsername(), frontendUrl + "/reset-password?token=" + resetToken);

            String htmlContent = templateEngine.process("password-reset", context);
            log.debug("Generated reset HTML content length: {}", htmlContent.length());

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(user.getEmail());
            helper.setSubject("Password Reset Request");
            helper.setText(htmlContent, true);

            log.info("Sending password reset email to {}", user.getEmail());
            mailSender.send(message);

            log.info("Password reset email successfully sent to: {}", user.getEmail());

        } catch (MessagingException e) {
            log.error("Failed to send password reset email to: {}", user.getEmail(), e);
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }
}
