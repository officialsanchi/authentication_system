package com.authentication.AuthenticationSystem.dtos.response;

import com.authentication.AuthenticationSystem.model.User;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserResponse {
    private Long id;
    private String username;
    private String fullName;
    private String email;
    private String phoneNumber;
    private String profilePhotoUrl;
    private boolean enabled;
    private boolean accountNonLocked;
    private boolean accountNonExpired;
    private boolean credentialsNonExpired;

    public static UserResponse from(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .phoneNumber(user.getPhoneNumber())
                .profilePhotoUrl(user.getProfilePhotoUrl())
                .enabled(user.isEnabled())
                .accountNonLocked(user.isAccountNonLocked())
                .accountNonExpired(user.isAccountNonExpired())
                .credentialsNonExpired(user.isCredentialsNonExpired())
                .build();
    }
}
