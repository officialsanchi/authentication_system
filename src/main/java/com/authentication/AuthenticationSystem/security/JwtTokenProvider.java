package com.authentication.AuthenticationSystem.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Component
@Slf4j
public class JwtTokenProvider {
    @Value("${spring.jwt.access-token.secret}")
    private String accessTokenSecret;

    @Value("${spring.jwt.refresh-token.secret}")
    private String refreshTokenSecret;

    @Value("${spring.jwt.access-token.expiration-ms}")
    private long accessTokenExpirationMs;

    private SecretKey accessKey;
    private SecretKey refreshKey;

    // ---------------------------------------------------------
    // INIT: LOAD AND BUILD SECRET KEYS
    // ---------------------------------------------------------
    @PostConstruct
    public void init() {
        log.info("🔐 Initializing JwtTokenProvider...");

        try {
            log.debug("Access token secret (length={}): {}",
                    accessTokenSecret.length(), accessTokenSecret);

            accessKey = Keys.hmacShaKeyFor(accessTokenSecret.getBytes(StandardCharsets.UTF_8));
            refreshKey = Keys.hmacShaKeyFor(refreshTokenSecret.getBytes(StandardCharsets.UTF_8));

            log.info("✔ Secret keys generated successfully.");
        } catch (Exception e) {
            log.error("❌ Failed to initialize JWT keys: {}", e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------
    // TOKEN GENERATION
    // ---------------------------------------------------------
    public String generateAccessToken(String username) {
        log.info("🔧 Generating ACCESS token for user: {}", username);

        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpirationMs);

        try {
            String token = Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(now)
                    .setExpiration(expiry)
                    .signWith(accessKey, SignatureAlgorithm.HS256)
                    .compact();

            log.debug("✔ Access token generated: {}", token);
            return token;

        } catch (Exception e) {
            log.error("❌ Error generating access token: {}", e.getMessage(), e);
            return null;
        }
    }

    public String generateRefreshToken(String username) {
        log.info("🔧 Generating REFRESH token for user: {}", username);

        Date now = new Date();
        Date expiry = new Date(now.getTime() + 604800000);

        try {
            String token = Jwts.builder()
                    .setId(UUID.randomUUID().toString())
                    .setSubject(username)
                    .claim("type", "refresh")
                    .setIssuedAt(now)
                    .setExpiration(expiry)
                    .signWith(refreshKey, SignatureAlgorithm.HS512)
                    .compact();

            log.debug("✔ Refresh token generated: {}", token);
            return token;

        } catch (Exception e) {
            log.error("❌ Error generating refresh token: {}", e.getMessage(), e);
            return null;
        }
    }

    // ---------------------------------------------------------
    // PARSING HELPERS
    // ---------------------------------------------------------
    private Claims parseAccessToken(String token) {
        log.debug("🔍 Parsing ACCESS token...");

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(accessKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            log.debug("✔ Access token parsed successfully. Claims: {}", claims);
            return claims;

        } catch (JwtException e) {
            log.error("❌ Access token parse error: {}", e.getMessage(), e);
            throw e;
        }
    }

    private Claims parseRefreshToken(String token) {
        log.debug("🔍 Parsing REFRESH token...");

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(refreshKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            log.debug("✔ Refresh token parsed successfully. Claims: {}", claims);
            return claims;

        } catch (JwtException e) {
            log.error("❌ Refresh token parse error: {}", e.getMessage(), e);
            throw e;
        }
    }

    // ---------------------------------------------------------
    // EXTRACT VALUES
    // ---------------------------------------------------------
    public String getUsernameFromAccessToken(String token) {
        log.debug("Extracting username from access token...");
        String username = parseAccessToken(token).getSubject();
        log.info("✔ Username extracted: {}", username);
        return username;
    }

    public Date getExpirationDateFromAccessToken(String token) {
        log.debug("Extracting expiration date from access token...");
        Date expiration = parseAccessToken(token).getExpiration();
        log.info("✔ Access token expires at: {}", expiration);
        return expiration;
    }

    // ---------------------------------------------------------
    // VALIDATION
    // ---------------------------------------------------------
    public boolean validateAccessToken(String token) {
        log.debug("Validating access token...");

        try {
            parseAccessToken(token);
            log.info("✔ Access token is valid.");
            return true;

        } catch (ExpiredJwtException e) {
            log.warn("⚠ Token expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("⚠ Token unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("⚠ Malformed token: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("⚠ Invalid signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("⚠ Illegal argument: {}", e.getMessage());
        } catch (Exception e) {
            log.error("❌ Unexpected token validation error: {}", e.getMessage(), e);
        }

        return false;
    }

    public long getAccessTokenExpirationMs() {
        return accessTokenExpirationMs;
    }
}
