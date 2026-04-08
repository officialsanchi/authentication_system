package com.authentication.AuthenticationSystem.service;

import com.authentication.AuthenticationSystem.model.AuditLog;
import com.authentication.AuthenticationSystem.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogService {
    private final AuditLogRepository auditLogRepository;

    @Async("auditTaskExecutor")
    @Transactional
    public void log(Long userId, String action, String entityType, String entityId,
                    String severity, String description, Map<String, Object> oldValues,
                    Map<String, Object> newValues, String ipAddress, String userAgent) {

        log.info("📥 [AuditLog] Incoming Log Request -> userId={}, action={}, entityType={}, entityId={}, severity={}, description={}, ipAddress={}, userAgent={}",
                userId, action, entityType, entityId, severity, description, ipAddress, userAgent);

        log.info("📌 [AuditLog] oldValues={}", oldValues);
        log.info("📌 [AuditLog] newValues={}", newValues);

        try {
            AuditLog auditLog = AuditLog.builder()
                    .userId(userId)
                    .action(action)
                    .entityType(entityType)
                    .entityId(entityId)
                    .severity(severity)
                    .description(description)
                    .oldValues(oldValues)
                    .newValues(newValues)

                    .userAgent(userAgent)
                    .build();

            log.info("🛠 [AuditLog] Constructed AuditLog Object: {}", auditLog);

            AuditLog saved = auditLogRepository.save(auditLog);
            log.info("✅ [AuditLog] Successfully saved audit log with ID={}", saved);
        } catch (Exception e) {
            log.error("❌ [AuditLog] Error saving audit log", e);
        }
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> getUserAuditLogs(Long userId, Pageable pageable) {
        log.info("🔍 [AuditLog] Fetching logs for userId={}, page={}", userId, pageable);

        Page<AuditLog> result = auditLogRepository.findByUserId(userId, pageable);

        log.info("📤 [AuditLog] Returned {} logs for userId={}", result.getTotalElements(), userId);

        return result;
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> getAuditLogsByAction(String action, Pageable pageable) {
        log.info("🔍 [AuditLog] Fetching logs by action='{}', page={}", action, pageable);

        Page<AuditLog> result = auditLogRepository.findByAction(action, pageable);

        log.info("📤 [AuditLog] Returned {} logs for action='{}'", result.getTotalElements(), action);

        return result;
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> getAuditLogsByTimeRange(LocalDateTime start, LocalDateTime end, Pageable pageable) {
        log.info("🔍 [AuditLog] Fetching logs from {} to {}, page={}", start, end, pageable);

        Page<AuditLog> result = auditLogRepository.findByTimeRange(start, end, pageable);

        log.info("📤 [AuditLog] Returned {} logs in time range", result.getTotalElements());

        return result;
    }
}
