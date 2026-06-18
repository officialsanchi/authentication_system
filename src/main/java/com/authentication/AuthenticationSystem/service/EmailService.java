package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    @Autowired
    private JavaMailSender mailSender;

    @Async
    public void sendOtpEmail(String to, String otp, String subject) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(to);
            helper.setSubject(subject); // FIXED: Using the passed subject parameter
            helper.setFrom("Security <no-reply@yourapp.com>");

            String htmlContent = String.format(
                    "<div style='font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;'>" +
                            "<h2 style='color: #1e293b;'>%s</h2>" +
                            "<p style='color: #64748b;'>Use the code below to proceed. Expires in 10 minutes.</p>" +
                            "<div style='background: #f1f5f9; padding: 24px; border-radius: 8px; text-align: center; margin: 24px 0;'>" +
                            "<span style='font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #6366f1;'>%s</span>" +
                            "</div>" +
                            "</div>", subject, otp);

            helper.setText(htmlContent, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            log.error("Failed to send HTML email", e);
        }
    }
}
