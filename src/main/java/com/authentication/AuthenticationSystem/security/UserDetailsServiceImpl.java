package com.authentication.AuthenticationSystem.security;

import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("🔍 [loadUserByUsername] Called with username: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.error("❌ [loadUserByUsername] User NOT found with username: {}", username);
                    return new UsernameNotFoundException("User not found with username: " + username);
                });

        log.info("✅ [loadUserByUsername] User found: id={}, username={}, email={}, enabled={}, emailVerified={}, accountNonLocked={}, roles={}",
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.isEnabled(),
                user.isEmailVerified(),
                user.isAccountNonLocked(),
                user.getRoles()
        );

        UserDetails userDetails = UserDetailsImpl.build(user);
        log.info("📦 [loadUserByUsername] Returning UserDetails: {}", userDetails);

        return userDetails;
    }

    @Transactional(readOnly = true)
    public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
        log.info("🔍 [loadUserByEmail] Called with email: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.error("❌ [loadUserByEmail] User NOT found with email: {}", email);
                    return new UsernameNotFoundException("User not found with email: " + email);
                });

        log.info("✅ [loadUserByEmail] User found: id={}, username={}, email={}, enabled={}, emailVerified={}, accountNonLocked={}, roles={}",
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.isEnabled(),
                user.isEmailVerified(),
                user.isAccountNonLocked(),
                user.getRoles()
        );

        UserDetails userDetails = UserDetailsImpl.build(user);
        log.info("📦 [loadUserByEmail] Returning UserDetails: {}", userDetails);

        return userDetails;
    }
}
