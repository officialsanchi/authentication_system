package com.authentication.AuthenticationSystem.repository;

import com.authentication.AuthenticationSystem.model.AuditLog;
import com.authentication.AuthenticationSystem.model.LoginAttempt;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    Page<AuditLog> findByUserId(Long userId, Pageable pageable);

    Page<AuditLog> findByAction(String action, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE a.createdAt BETWEEN :start AND :end")
    Page<AuditLog> findByTimeRange(@Param("start") LocalDateTime start,
                                   @Param("end") LocalDateTime end,
                                   Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId AND a.action = :action")
    List<AuditLog> findByUserAndAction(@Param("userId") Long userId, @Param("action") String action);
}
