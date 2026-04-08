package com.authentication.AuthenticationSystem.security;

import com.authentication.AuthenticationSystem.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter  extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        log.info("🔥 JwtAuthenticationFilter triggered for path: {}", request.getRequestURI());

        try {
            // Step 1: Read Authorization header
            log.debug("Reading Authorization header...");
            String jwt = getJwtFromRequest(request);

            if (!StringUtils.hasText(jwt)) {
                log.debug("No JWT found in request.");
            } else {
                log.info("JWT detected in request: {}", jwt);

                // Step 2: Validate JWT
                log.debug("Validating JWT...");
                boolean valid = tokenProvider.validateAccessToken(jwt);

                if (!valid) {
                    log.warn("❌ JWT validation failed.");
                } else {
                    log.info("✔ JWT is valid.");

                    // Step 3: Check blacklist
                    log.debug("Checking if token is blacklisted...");
                    if (tokenBlacklistService.isBlacklisted(jwt)) {
                        log.warn("🚫 Token is blacklisted! Rejecting request.");
                        filterChain.doFilter(request, response);
                        return;
                    }

                    // Step 4: Extract username
                    log.debug("Extracting username from token...");
                    String username = tokenProvider.getUsernameFromAccessToken(jwt);
                    log.info("Username extracted from token: {}", username);

                    // Step 5: Load user from DB
                    log.debug("Loading user details from UserDetailsService...");
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    log.info("User loaded: {}", userDetails.getUsername());

                    // Step 6: Build authentication object
                    log.debug("Building authentication object...");
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // Step 7: Set authentication into context
                    log.debug("Setting authentication in SecurityContext...");
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info("✔ Authentication set for user: {}", username);
                }
            }

        } catch (Exception ex) {
            log.error("❌ ERROR inside JwtAuthenticationFilter", ex);
        }

        log.debug("Continuing filter chain...");
        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        log.debug("Extracting JWT from Authorization header...");

        String bearerToken = request.getHeader("Authorization");

        if (bearerToken == null) {
            log.debug("Authorization header is missing.");
            return null;
        }

        log.debug("Authorization header: {}", bearerToken);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            log.info("Bearer token format detected.");
            return bearerToken.substring(7);
        }

        log.warn("Authorization header does not start with Bearer.");
        return null;
    }
}
