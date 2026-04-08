package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.LoginAttempt;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.LoginAttemptRepository;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    @Value("${security.max-login-attempts:5}")
    private int maxAttempts;

    @Value("${security.lockout-duration-minutes:30}")
    private int lockoutDurationMinutes;

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;

    @Async("auditTaskExecutor")
    @Transactional
    public void recordAttempt(String username, String ipAddress, boolean successful,
                              String failureReason, HttpServletRequest request) {
        try {
            log.info("=== Recording Login Attempt ===");
            log.debug("Incoming data -> username: {}, ip: {}, successful: {}, failureReason: {}, userAgent: {}",
                    username, ipAddress, successful, failureReason, request.getHeader("User-Agent"));

            LoginAttempt attempt = LoginAttempt.builder()
                    .username(username)
                    .ipAddress(ipAddress)
                    .successful(successful)
                    .failureReason(failureReason)
                    .userAgent(request.getHeader("User-Agent"))
                    .build();

            log.debug("LoginAttempt object created: {}", attempt);

            loginAttemptRepository.save(attempt);
            log.info("Login attempt saved for username: {}", username);

            if (!successful) {
                log.warn("Failed login attempt detected for user: {}", username);
                checkAndLockAccount(username);
            }

        } catch (Exception e) {
            log.error("Error recording login attempt for user: {}", username, e);
        }
    }

    @Transactional(readOnly = true)
    public boolean isBlocked(String username) {
        log.info("Checking if user '{}' is blocked", username);

        User user = userRepository.findByUsername(username).orElse(null);
        log.debug("Fetched user object: {}", user);

        if (user == null) {
            log.warn("User '{}' does not exist. Cannot be blocked.", username);
            return false;
        }

        if (!user.isAccountNonLocked()) {
            log.warn("User '{}' is currently locked. Checking expiration...", username);

            if (user.getLockedUntil() != null &&
                    LocalDateTime.now().isAfter(user.getLockedUntil())) {

                log.info("Lock expired for user '{}'. Unlocking account.", username);
                unlockAccount(user.getId());
                return false;
            }

            log.warn("User '{}' is still locked until {}", username, user.getLockedUntil());
            return true;
        }

        log.info("User '{}' is not blocked.", username);
        return false;
    }

    @Transactional
    protected void checkAndLockAccount(String username) {
        log.info("Checking failed login count for user '{}'", username);

        LocalDateTime since = LocalDateTime.now().minusMinutes(lockoutDurationMinutes);
        long failedAttempts = loginAttemptRepository.countFailedAttempts(username, since);

        log.debug("Failed attempts for '{}': {} since {}", username, failedAttempts, since);

        if (failedAttempts >= maxAttempts) {

            User user = userRepository.findByUsername(username).orElse(null);
            log.debug("User object fetched for lock processing: {}", user);

            if (user != null && user.isAccountNonLocked()) {
                LocalDateTime unlockTime = LocalDateTime.now().plusMinutes(lockoutDurationMinutes);

                log.warn("Locking account for user: {} until {}", username, unlockTime);
                userRepository.updateLockStatus(user.getId(), false, unlockTime);

                log.info("Account locked for user {}. Reason: too many failed attempts.", username);
            } else {
                log.warn("User '{}' already locked or does not exist.", username);
            }
        } else {
            log.info("User '{}' has insufficient failed attempts for lockout ({} / {})",
                    username, failedAttempts, maxAttempts);
        }
    }

    @Transactional
    public void unlockAccount(Long userId) {
        log.info("Unlocking account for user ID: {}", userId);
        userRepository.updateLockStatus(userId, true, null);
        log.info("Account unlocked for user ID: {}", userId);
    }

    @Transactional(readOnly = true)
    public List<LoginAttempt> getRecentAttempts(String username, int minutes) {
        log.info("Fetching recent failed login attempts for user '{}' within last {} minutes", username, minutes);

        LocalDateTime since = LocalDateTime.now().minusMinutes(minutes);
        List<LoginAttempt> attempts = loginAttemptRepository.findRecentFailedAttempts(username, since);

        log.debug("Found {} recent attempts for '{}': {}", attempts.size(), username, attempts);

        return attempts;
    }
}
