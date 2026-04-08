package com.authentication.AuthenticationSystem.security;

import com.authentication.AuthenticationSystem.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@Builder
@Slf4j
public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;
    private String username;
    private String email;

    @JsonIgnore
    private String password;

    private boolean enabled;
    private boolean accountNonLocked;
    private Collection<? extends GrantedAuthority> authorities;

    public static UserDetailsImpl build(User user) {
        log.info("Building UserDetailsImpl from user: id={}, username={}, email={}, enabled={}, emailVerified={}, accountNonLocked={}",
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.isEnabled(),
                user.isEmailVerified(),
                user.isAccountNonLocked()
        );

        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> {
                    log.info("Mapping role: {}", role.name());
                    return new SimpleGrantedAuthority(role.name());
                })
                .collect(Collectors.toList());

        log.info("Final authorities list: {}", authorities);

        UserDetailsImpl userDetails = UserDetailsImpl.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .password("[PROTECTED]")
                .enabled(user.isEnabled() && user.isEmailVerified())
                .accountNonLocked(user.isAccountNonLocked())
                .authorities(authorities)
                .build();

        log.info("Created UserDetailsImpl: {}", userDetails);

        return userDetails;
    }

    @Override
    public boolean isAccountNonExpired() {
        log.debug("Checking account expiration for user {} -> true", username);
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        log.debug("Checking credentials expiration for user {} -> true", username);
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        log.debug("Account Non-Locked check for user {} -> {}", username, accountNonLocked);
        return accountNonLocked;
    }

    @Override
    public boolean isEnabled() {
        log.debug("Enabled check for user {} -> {}", username, enabled);
        return enabled;
    }
}
