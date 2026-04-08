package com.authentication.AuthenticationSystem.model;

import com.authentication.AuthenticationSystem.enums.Roles;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


@Entity
@Table(name = "users",
        indexes = {
                @Index(name = "idx_user_email", columnList = "email", unique = true),
                @Index(name = "idx_user_username", columnList = "username", unique = true)
        })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @NotBlank
        @Size(max = 50)
        @Column(nullable = false, unique = true)
        private String username;

        @NotBlank
        @Size(max = 100)
        @Email
        @Column(nullable = false, unique = true)
        private String email;

        @NotBlank
        @Size(max = 120)
        @Column(nullable = false)
        private String password;

        @ElementCollection(fetch = FetchType.EAGER)
        @CollectionTable(
                name = "user_roles",
                joinColumns = @JoinColumn(name = "user_id"),
                indexes = @Index(name = "idx_user_roles", columnList = "user_id")
        )
        @Enumerated(EnumType.STRING)
        @Column(name = "role")
        @Builder.Default
        private Set<Roles> roles = new HashSet<>();

        @Column(nullable = false)
        @Builder.Default
        private boolean emailVerified = false;

        @Column(nullable = false)
        @Builder.Default
        private boolean enabled = true;

        @Column(nullable = false)
        @Builder.Default
        private boolean accountNonLocked = true;

        @Column
        private LocalDateTime lockedUntil;

        @CreationTimestamp
        @Column(nullable = false, updatable = false)
        private LocalDateTime createdAt;

        @UpdateTimestamp
        @Column(nullable = false)
        private LocalDateTime updatedAt;


        @Column
        private String phoneNumber;
         @Column
         private String confirmPassword;

        @Column
        private String firstName;

        @Column
        private String lastName;;

        @Column
        private LocalDateTime lastLoginAt;

        @Column
        private String lastLoginIp;

        @Version
        private Long version;


        }



