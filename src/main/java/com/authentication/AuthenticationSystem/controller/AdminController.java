package com.authentication.AuthenticationSystem.controller;

import com.authentication.AuthenticationSystem.dtos.response.MessageResponse;
import com.authentication.AuthenticationSystem.model.AuditLog;
import com.authentication.AuthenticationSystem.model.User;
import com.authentication.AuthenticationSystem.repository.UserRepository;
import com.authentication.AuthenticationSystem.service.AuditLogService;
import com.authentication.AuthenticationSystem.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    private final LoginAttemptService loginAttemptService;

    @GetMapping("/users")
    public ResponseEntity<Page<User>> getAllUsers(Pageable pageable) {
        return ResponseEntity.ok(userRepository.findAll(pageable));
    }

    @PostMapping("/users/{id}/unlock")
    public ResponseEntity<MessageResponse> unlockUserAccount(@PathVariable Long id) {
        loginAttemptService.unlockAccount(id);
        return ResponseEntity.ok(MessageResponse.success("Account unlocked successfully"));
    }

    @GetMapping("/audit-logs")
    public ResponseEntity<Page<AuditLog>> getAuditLogs(
            @RequestParam(required = false) String action,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end,
            Pageable pageable) {

        Page<AuditLog> logs;
        if (action != null) {
            logs = auditLogService.getAuditLogsByAction(action, pageable);
        } else if (start != null && end != null) {
            logs = auditLogService.getAuditLogsByTimeRange(start, end, pageable);
        } else {
            logs = auditLogService.getUserAuditLogs(null, pageable);
        }

        return ResponseEntity.ok(logs);
    }

    @GetMapping("/audit-logs/user/{userId}")
    public ResponseEntity<Page<AuditLog>> getUserAuditLogs(@PathVariable Long userId, Pageable pageable) {
        return ResponseEntity.ok(auditLogService.getUserAuditLogs(userId, pageable));
    }
}
