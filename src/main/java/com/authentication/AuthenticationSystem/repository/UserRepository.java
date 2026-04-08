package com.authentication.AuthenticationSystem.repository;

import com.authentication.AuthenticationSystem.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
    Optional<User> findByPhoneNumber(String phoneNumber);
    boolean existsByPhoneNumber(String phoneNumber);


    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :time, u.lastLoginIp = :ip WHERE u.id = :id")
    void updateLastLogin(@Param("id") Long id, @Param("time") LocalDateTime time, @Param("ip") String ip);

    @Modifying
    @Query("UPDATE User u SET u.accountNonLocked = :locked, u.lockedUntil = :until WHERE u.id = :id")
    void updateLockStatus(@Param("id") Long id, @Param("locked") boolean locked, @Param("until") LocalDateTime until);

    @Modifying
    @Query("UPDATE User u SET u.emailVerified = true WHERE u.id = :id")
    void verifyEmail(@Param("id") Long id);

    @Modifying
    @Query("UPDATE User u SET u.password = :password WHERE u.id = :id")
    void updatePassword(@Param("id") Long id, @Param("password") String password);
}
