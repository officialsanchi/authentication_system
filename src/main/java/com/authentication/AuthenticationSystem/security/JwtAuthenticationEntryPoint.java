package com.authentication.AuthenticationSystem.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public JwtAuthenticationEntryPoint() {
        log.info("Initializing JwtAuthenticationEntryPoint...");

        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        log.info("ObjectMapper configured successfully for JwtAuthenticationEntryPoint.");
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException, ServletException {

        log.error("🚨 Entered JwtAuthenticationEntryPoint.commence()");
        log.error("Unauthorized error detected!");
        log.error("Message: {}", authException.getMessage());
        log.error("Request URI: {}", request.getRequestURI());
        log.error("HTTP Method: {}", request.getMethod());
        log.error("Remote Address: {}", request.getRemoteAddr());

        try {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            log.info("Response status set to 401 - UNAUTHORIZED.");

            Map<String, Object> body = new HashMap<>();
            body.put("timestamp", LocalDateTime.now().toString());
            body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            body.put("error", "Unauthorized");
            body.put("message", authException.getMessage());
            body.put("path", request.getRequestURI());

            log.info("Writing JSON error response body...");

            objectMapper.writeValue(response.getOutputStream(), body);

            log.info("JSON error response written successfully.");
        } catch (Exception ex) {
            log.error("❌ Error while writing unauthorized response body: {}", ex.getMessage(), ex);
            throw ex;
        }

        log.info("JwtAuthenticationEntryPoint.commence() completed.");
    }
}
