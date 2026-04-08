package com.authentication.AuthenticationSystem.repository;

import com.authentication.AuthenticationSystem.model.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {

    Optional<TokenBlacklist> findByToken(String token);

    boolean existsByToken(String token);

    @Modifying
    @Query("DELETE FROM TokenBlacklist t WHERE t.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") Instant now);
}
