package com.authentication.AuthenticationSystem.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "token_blacklist", indexes = {
        @Index(name = "idx_expiry_date", columnList = "expiry_date")  // ✅ index name fixed
})
public class TokenBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 512)
    private String token;

    @Column(name = "expiry_date", nullable = false)  // ✅ explicit column name added
    private Instant expiryDate;

    @Column(nullable = false)
    private String tokenType;

    @Column(nullable = false)
    private String reason;

    @Column(nullable = false)
    private Long userId;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
