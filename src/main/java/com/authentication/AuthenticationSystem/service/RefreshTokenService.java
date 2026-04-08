package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.dtos.response.JwtResponse;
import com.authentication.AuthenticationSystem.exception.TokenRefreshException;
import com.authentication.AuthenticationSystem.model.RefreshToken;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.RefreshTokenRepository;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import com.authentication.AuthenticationSystem.security.JwtTokenProvider;

import com.authentication.AuthenticationSystem.utilities.SecurityUtil;
import jakarta.servlet.http.HttpServletRequest;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    @Value("${jwt.refresh-token.expiration-ms}")
    private long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtTokenProvider tokenProvider;
    private final AuditLogService auditLogService;

    @Transactional
    public String createRefreshToken(Long userId, HttpServletRequest request) {
        log.info("=== Creating Refresh Token ===");
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        log.debug("User for refresh token: {}", user);

        // Delete existing refresh token
        refreshTokenRepository.findByUserId(userId)
                .ifPresent(existing -> {
                    log.debug("Deleting existing refresh token: {}", existing);
                    refreshTokenRepository.delete(existing);
                });

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .deviceInfo(SecurityUtil.getDeviceInfo(request))
                .ipAddress(SecurityUtil.getClientIP(request))
                .revoked(false)
                .build();

        log.debug("Created RefreshToken object: {}", refreshToken);

        refreshToken = refreshTokenRepository.save(refreshToken);
        log.info("Saved refresh token for user {}: {}", userId, refreshToken);

        return refreshToken.getToken();
    }

    @Transactional(readOnly = true)
    public RefreshToken verifyExpiration(RefreshToken token) {
        log.debug("Verifying refresh token expiration: {}", token);

        if (token.isRevoked()) {
            log.warn("Refresh token is revoked: {}", token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was revoked");
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            log.warn("Refresh token expired: {}", token);
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token expired. Please login again");
        }

        log.debug("Refresh token is valid: {}", token);
        return token;
    }

    @Transactional
    public JwtResponse refreshAccessToken(String requestRefreshToken, HttpServletRequest request) {
        log.info("=== Refreshing Access Token ===");
        log.debug("Received refresh token: {}", requestRefreshToken);

        RefreshToken refreshToken = refreshTokenRepository.findByToken(requestRefreshToken)
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token not found"));

        log.debug("Fetched RefreshToken: {}", refreshToken);

        verifyExpiration(refreshToken);

        User user = refreshToken.getUser();
        log.debug("User associated with token: {}", user);

        // Generate new tokens
        String newAccessToken = tokenProvider.generateAccessToken(user.getUsername());
        String newRefreshToken = createRefreshToken(user.getId(), request);

        // Revoke old refresh token
        refreshTokenRepository.delete(refreshToken);
        log.debug("Deleted old refresh token: {}", refreshToken);

        // Audit log
        auditLogService.log(
                user.getId(),
                "TOKEN_REFRESH",
                "RefreshToken",
                refreshToken.getId().toString(),
                "INFO",
                "Access token refreshed",
                null,
                null,
                SecurityUtil.getClientIP(request),
                request.getHeader("User-Agent")
        );

        JwtResponse response = JwtResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .type("Bearer")
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles().stream().map(Enum::name).toList())
                .emailVerified(user.isEmailVerified())
                .expiresIn(tokenProvider.getAccessTokenExpirationMs() / 1000)
                .build();

        log.debug("Returning JwtResponse: {}", response);
        return response;
    }

    @Transactional
    public void revokeRefreshToken(String token) {
        log.info("Revoking refresh token: {}", token);
        refreshTokenRepository.findByToken(token)
                .ifPresent(refreshToken -> {
                    refreshToken.setRevoked(true);
                    refreshTokenRepository.save(refreshToken);
                    log.debug("Token revoked: {}", refreshToken);
                });
    }

    @Transactional
    public void revokeAllUserTokens(Long userId) {
        log.info("Revoking all refresh tokens for user: {}", userId);
        refreshTokenRepository.revokeByUserId(userId);
    }

    @Transactional
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(Instant.now());
        log.info("Cleaned up expired refresh tokens");
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
