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
    @Query("""
            SELECT u
            FROM User u
            WHERE LOWER(u.username) = LOWER(:login)
               OR LOWER(u.email) = LOWER(:login)
               OR LOWER(u.phoneNumber) = LOWER(:login)
            """)
    Optional<User> findByAnyIdentifier(@Param("login") String login);

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);
}
