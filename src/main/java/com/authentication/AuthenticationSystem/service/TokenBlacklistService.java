package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.TokenBlacklist;
import com.authentication.AuthenticationSystem.repository.TokenBlacklistRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {
    private final TokenBlacklistRepository tokenBlacklistRepository;

    @Transactional
    public void blacklistToken(String token, String tokenType, Instant expiryDate,
                               String reason, Long userId) {
        TokenBlacklist blacklistEntry = TokenBlacklist.builder()
                .token(token)
                .tokenType(tokenType)
                .expiryDate(expiryDate)
                .reason(reason)
                .userId(userId)
                .build();

        log.debug("Creating TokenBlacklist object: {}", blacklistEntry);

        tokenBlacklistRepository.save(blacklistEntry);

        log.info("Token blacklisted: {}", blacklistEntry);
    }

    @Transactional(readOnly = true)
    public boolean isBlacklisted(String token) {
        boolean result = tokenBlacklistRepository.existsByToken(token);
        log.debug("Check if token is blacklisted: {} -> {}", token, result);
        return result;
    }

    @Scheduled(cron = "0 0 */6 * * *") // Run every 6 hours
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired blacklisted tokens at {}", Instant.now());
        tokenBlacklistRepository.deleteExpiredTokens(Instant.now());
        log.info("Expired blacklisted tokens cleanup completed");
    }
}
