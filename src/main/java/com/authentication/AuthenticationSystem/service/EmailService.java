package com.authentication.AuthenticationSystem.service;

import com.resend.Resend;
import com.resend.core.exception.ResendException;
import com.resend.services.emails.model.CreateEmailOptions;
;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;


@Service

@Slf4j

public class EmailService {private final Resend resend;
    private final String fromEmail;

    public EmailService(
            @Value("${RESEND_API_KEY}") String resendApiKey,
            @Value("${RESEND_FROM_EMAIL:onboarding@resend.dev}") String fromEmail
    ) {
        this.resend = new Resend(resendApiKey);
        this.fromEmail = fromEmail;
    }

    @Async
    public void sendOtpEmail(String to, String otp, String subject) {

        String htmlContent = String.format(
                "<div style='font-family: sans-serif; max-width: 600px; margin: 0 auto; " +
                        "padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;'>" +

                        "<h2 style='color: #1e293b;'>%s</h2>" +

                        "<p style='color: #64748b;'>" +
                        "Use the code below to proceed. Expires in 10 minutes." +
                        "</p>" +

                        "<div style='background: #f1f5f9; padding: 24px; " +
                        "border-radius: 8px; text-align: center; margin: 24px 0;'>" +

                        "<span style='font-size: 32px; font-weight: bold; " +
                        "letter-spacing: 5px; color: #6366f1;'>%s</span>" +

                        "</div>" +
                        "</div>",
                subject,
                otp
        );

        try {

            CreateEmailOptions params = CreateEmailOptions.builder()
                    .from(fromEmail)
                    .to(to)
                    .subject(subject)
                    .html(htmlContent)
                    .build();

            resend.emails().send(params);

            log.info("OTP email sent successfully.");

        } catch (ResendException e) {

            log.error("Failed to send OTP email.", e);
        }
    }
}
