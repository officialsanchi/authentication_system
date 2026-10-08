package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String identifier)
            throws UsernameNotFoundException {
        User user = userRepository.
                findByAnyIdentifier(identifier)
                .orElseThrow(() -> new
                        UsernameNotFoundException(
                                "User not found with identifier: "
                                        + identifier ) );
                  return org.springframework.
                security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .authorities("USER")
                .accountLocked(!user.isEnabled())
                .build(); }
}
