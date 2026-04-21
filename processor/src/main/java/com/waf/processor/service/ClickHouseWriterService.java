package com.waf.processor.service;

import com.waf.common.model.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@Slf4j
public class ClickHouseWriterService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final JdbcTemplate jdbcTemplate;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private boolean enableAsync = true;

    public ClickHouseWriterService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void writeEvent(SecurityEvent event) {
        if (enableAsync) {
            CompletableFuture.runAsync(() -> doWriteEvent(event), executor)
                .exceptionally(ex -> {
                    log.error("Failed to write event: {}", ex.getMessage());
                    return null;
                });
        } else {
            doWriteEvent(event);
        }
    }

    public void writeEventsBatch(java.util.List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return;
        }

        StringBuilder sql = new StringBuilder("INSERT INTO security_events VALUES ");
        boolean first = true;

        for (SecurityEvent event : events) {
            if (!first) {
                sql.append(", ");
            }
            sql.append("(");
            sql.append("'").append(event.getEventId()).append("', ");
            sql.append("'").append(formatTimestamp(event.getTimestamp())).append("', ");
            sql.append("'").append(event.getSourceIp()).append("', ");
            sql.append("'").append(sanitize(event.getUserAgent())).append("', ");
            sql.append("'").append(sanitize(event.getRequestPath())).append("', ");
            sql.append("'").append(event.getRequestMethod()).append("', ");
            sql.append("'").append(event.getThreatType()).append("', ");
            sql.append(event.getThreatScore() != null ? event.getThreatScore() : 0).append(", ");
            sql.append("'").append(event.getCountryCode() != null ? event.getCountryCode() : "XX").append("', ");
            sql.append(event.getIsBlocked() ? 1 : 0).append(", ");
            sql.append(event.getResponseTimeMs() != null ? event.getResponseTimeMs() : 0);
            sql.append(")");
            first = false;
        }

        try {
            jdbcTemplate.execute(sql.toString());
            log.debug("Wrote {} events to ClickHouse", events.size());
        } catch (Exception e) {
            log.error("Failed to write batch: {}", e.getMessage());
        }
    }

    private void doWriteEvent(SecurityEvent event) {
        String sql = "INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try {
            jdbcTemplate.update(sql,
                event.getEventId(),
                formatTimestamp(event.getTimestamp()),
                event.getSourceIp(),
                sanitize(event.getUserAgent()),
                sanitize(event.getRequestPath()),
                event.getRequestMethod(),
                event.getThreatType().name(),
                event.getThreatScore() != null ? event.getThreatScore() : 0,
                event.getCountryCode() != null ? event.getCountryCode() : "XX",
                event.getIsBlocked() ? 1 : 0,
                event.getResponseTimeMs() != null ? event.getResponseTimeMs() : 0
            );
            log.debug("Wrote event {} to ClickHouse", event.getEventId());
        } catch (Exception e) {
            log.error("Failed to write event to ClickHouse: {}", e.getMessage());
        }
    }

    private String formatTimestamp(Instant timestamp) {
        if (timestamp == null) {
            return Instant.now().atOffset(ZoneOffset.UTC).format(FORMATTER);
        }
        return timestamp.atOffset(ZoneOffset.UTC).format(FORMATTER);
    }

    private String sanitize(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("'", "''").replace("\n", "").replace("\r", "");
    }

    public void flush() {
        log.info("Flushing ClickHouse writer buffer");
    }

    public void shutdown() {
        executor.shutdown();
    }
}