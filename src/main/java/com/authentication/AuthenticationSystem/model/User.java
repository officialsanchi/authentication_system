package com.authentication.AuthenticationSystem.model;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Setter
@Builder // For AuthService
@NoArgsConstructor // FIX: Required by JPA/Hibernate
@AllArgsConstructor
public class User {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(unique = true, nullable = false)
        private String username;

        @Column(unique = true, nullable = false)
        private String email;

        private String phoneNumber;
        private String password;
        private String profilePhotoUrl;

        @Builder.Default
        private boolean enabled = false;

        @Builder.Default
        private boolean accountNonLocked = true;

        @Builder.Default
        private boolean accountNonExpired = true;

        @Builder.Default
        private boolean credentialsNonExpired = true;

        private String otpCode;
        private LocalDateTime otpExpiry;
        private String photoUrl;

        private String resetOtpCode;     // Dedicated only for password resets
        private LocalDateTime resetOtpExpiry;
        }



