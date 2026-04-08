package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.dtos.request.LoginRequest;
import com.authentication.AuthenticationSystem.dtos.request.RegisterRequest;
import com.authentication.AuthenticationSystem.dtos.response.JwtResponse;
import com.authentication.AuthenticationSystem.dtos.response.MessageResponse;
import com.authentication.AuthenticationSystem.enums.Roles;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import com.authentication.AuthenticationSystem.security.JwtTokenProvider;
import com.authentication.AuthenticationSystem.security.UserDetailsImpl;
import com.authentication.AuthenticationSystem.utilities.SecurityUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final EmailService emailService;
    private final LoginAttemptService loginAttemptService;
    private final AuditLogService auditLogService;
    private final TokenBlacklistService tokenBlacklistService;

    @Transactional
    public JwtResponse authenticateUser(LoginRequest loginRequest, HttpServletRequest request) {

        log.info("🔐 AUTH ATTEMPT: loginRequest={}", loginRequest);

        String ipAddress = SecurityUtil.getClientIP(request);
        log.info("🌐 Client IP: {}", ipAddress);

        String username = loginRequest.getUsername();
        log.info("👤 Username: {}", username);

        // Check if blocked
        if (loginAttemptService.isBlocked(username)) {
            log.warn("⛔ User '{}' is blocked due to failed attempts", username);

            loginAttemptService.recordAttempt(username, ipAddress, false, "Account locked", request);
            throw new LockedException("Account is temporarily locked due to too many failed attempts");
        }

        try {
            log.info("🔍 Authenticating user '{}'", username);

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            username,
                            loginRequest.getPassword()
                    )
            );

            log.info("✅ Authentication successful: {}", authentication);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            log.info("📌 UserDetails loaded: {}", userDetails);

            if (!userDetails.isEnabled()) {
                log.warn("⚠️ Email not verified for user '{}'", username);
                throw new DisabledException("Email not verified. Please verify your email first.");
            }

            // Generate tokens
            String accessToken = tokenProvider.generateAccessToken(username);
            String refreshToken = refreshTokenService.createRefreshToken(userDetails.getId(), request);

            log.info("🔑 Generated AccessToken: {}", accessToken);
            log.info("🔄 Generated RefreshToken: {}", refreshToken);

            // Update last login
            userRepository.updateLastLogin(
                    userDetails.getId(),
                    LocalDateTime.now(),
                    ipAddress
            );

            log.info("📅 Updated last login for userId={}", userDetails.getId());

            // Record successful login
            loginAttemptService.recordAttempt(username, ipAddress, true, null, request);

            // Audit log
            auditLogService.log(
                    userDetails.getId(),
                    "LOGIN",
                    "User",
                    userDetails.getId().toString(),
                    "INFO",
                    "User logged in successfully",
                    null,
                    null,
                    ipAddress,
                    request.getHeader("User-Agent")
            );

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            log.info("🎭 User roles: {}", roles);

            JwtResponse response = JwtResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .type("Bearer")
                    .id(userDetails.getId())
                    .username(userDetails.getUsername())
                    .email(userDetails.getEmail())
                    .roles(roles)
                    .emailVerified(true)
                    .expiresIn(tokenProvider.getAccessTokenExpirationMs() / 1000)
                    .build();

            log.info("📤 AUTH RESPONSE: {}", response);

            return response;

        } catch (BadCredentialsException e) {
            log.error("❌ Invalid credentials for username={}", username);

            loginAttemptService.recordAttempt(username, ipAddress, false, "Invalid credentials", request);
            throw new BadCredentialsException("Invalid username or password");

        } catch (DisabledException | LockedException e) {
            log.error("⚠️ Account disabled or locked: {}", e.getMessage());
            throw e;

        } catch (Exception e) {
            log.error("🔥 Authentication failed: {}", e.getMessage(), e);

            loginAttemptService.recordAttempt(username, ipAddress, false, e.getMessage(), request);
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }
    }


    // ----------------------------------------------------------
    // REGISTER USER
    // ----------------------------------------------------------

    @Transactional
    public MessageResponse registerUser(RegisterRequest registerRequest, HttpServletRequest request) {

        log.info("📝 REGISTER REQUEST: {}", registerRequest);

        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            log.warn("⛔ Username '{}' already exists", registerRequest.getUsername());
            return MessageResponse.error("Username is already taken!");
        }

        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            log.warn("⛔ Email '{}' already exists", registerRequest.getEmail());
            return MessageResponse.error("Email is already in use!");
        }

        if (userRepository.existsByPhoneNumber(registerRequest.getPhoneNumber())) {
            log.warn("⛔ Phone number '{}' already exists", registerRequest.getPhoneNumber());
            return MessageResponse.error("Phone number is already in use!");
        }

        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setLastName(registerRequest.getLastName());
        user.setPhoneNumber(registerRequest.getPhoneNumber());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword())); // do NOT log password
        user.setEmailVerified(false);
        user.setEnabled(true);
        user.setAccountNonLocked(true);

        log.info("👤 USER BEFORE ROLE ASSIGNMENT: {}", user);

        // Set roles
        Set<String> strRoles = registerRequest.getRoles();
        Set<Roles> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            roles.add(Roles.ROLE_USER);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "admin" -> roles.add(Roles.ROLE_ADMIN);
                    case "moderator" -> roles.add(Roles.ROLE_MODERATOR);
                    default -> roles.add(Roles.ROLE_USER);
                }
            });
        }

        user.setRoles(roles);

        log.info("🎭 ASSIGNED ROLES: {}", roles);
        log.info("👤 FINAL USER OBJECT: {}", user);

        User savedUser = userRepository.save(user);

        log.info("💾 SAVED USER: {}", savedUser);

        emailService.sendVerificationEmail(savedUser);
        log.info("📧 Verification email sent to {}", savedUser.getEmail());

        auditLogService.log(
                savedUser.getId(),
                "REGISTER",
                "User",
                savedUser.getId().toString(),
                "INFO",
                "New user registered",
                null,
                null,
                SecurityUtil.getClientIP(request),
                request.getHeader("User-Agent")
        );

        return MessageResponse.success("User registered successfully! Please check your email to verify your account.");
    }


    // ----------------------------------------------------------
    // REFRESH TOKEN
    // ----------------------------------------------------------

    @Transactional
    public JwtResponse refreshToken(String refreshToken, HttpServletRequest request) {
        log.info("🔄 REFRESH TOKEN REQUEST: {}", refreshToken);
        return refreshTokenService.refreshAccessToken(refreshToken, request);
    }


    // ----------------------------------------------------------
    // LOGOUT
    // ----------------------------------------------------------

    @Transactional
    public MessageResponse logout(String accessToken, String refreshToken, HttpServletRequest request) {

        log.info("🚪 LOGOUT REQUEST: accessToken={}, refreshToken={}", accessToken, refreshToken);

        if (accessToken != null && tokenProvider.validateAccessToken(accessToken)) {
            Date expiryDate = tokenProvider.getExpirationDateFromAccessToken(accessToken);

            log.info("📅 Access Token Expiration: {}", expiryDate);

            Instant expiryInstant = expiryDate.toInstant();

            tokenBlacklistService.blacklistToken(
                    accessToken,
                    "ACCESS",
                    expiryInstant,
                    "LOGOUT",
                    getCurrentUserId()
            );

            log.info("📝 Access token blacklisted");
        }

        if (refreshToken != null) {
            refreshTokenService.revokeRefreshToken(refreshToken);
            log.info("🗑 Refresh token revoked");
        }

        auditLogService.log(
                getCurrentUserId(),
                "LOGOUT",
                "User",
                String.valueOf(getCurrentUserId()),
                "INFO",
                "User logged out",
                null,
                null,
                SecurityUtil.getClientIP(request),
                request.getHeader("User-Agent")
        );

        SecurityContextHolder.clearContext();
        log.info("🧹 Security context cleared");

        return MessageResponse.success("Logged out successfully");
    }


    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("👤 Current authentication: {}", authentication);

        if (authentication != null && authentication.getPrincipal() instanceof UserDetailsImpl user) {
            log.info("🔐 Current userId={}", user.getId());
            return user.getId();
        }
        log.warn("⚠️ No authenticated user found");
        return null;
    }
}
