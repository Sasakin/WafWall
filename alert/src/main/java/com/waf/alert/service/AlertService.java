package com.waf.alert.service;

import com.waf.common.model.Alert;
import com.waf.common.model.ThreatType;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Gauge;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
@Slf4j
public class AlertService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final BlocklistService blocklistService;
    private final TelegramNotificationService telegramService;
    private final WebSocketAlertService webSocketService;

    @Value("${alert.deduplication-window-seconds:300}")
    private int deduplicationWindowSeconds;

    @Value("${alert.auto-block-threshold:50}")
    private int autoBlockThreshold;

    private final Set<String> processedAlertIds = ConcurrentHashMap.newKeySet();
    private final Map<String, AlertStats> alertStats = new ConcurrentHashMap<>();
    private final AtomicLong totalProcessed = new AtomicLong(0);
    private final AtomicLong totalDuplicates = new AtomicLong(0);
    private final AtomicLong ipsAutoBlocked = new AtomicLong(0);
    private final Counter alertsCounter;
    private final Counter duplicatesCounter;
    private final Counter blockedCounter;
    private final Counter telegramCounter;

    public AlertService(
            RedisTemplate<String, Object> redisTemplate,
            BlocklistService blocklistService,
            TelegramNotificationService telegramService,
            WebSocketAlertService webSocketService,
            MeterRegistry meterRegistry) {
        this.redisTemplate = redisTemplate;
        this.blocklistService = blocklistService;
        this.telegramService = telegramService;
        this.webSocketService = webSocketService;

        this.alertsCounter = Counter.builder("alerts_processed_total")
            .description("Total alerts processed")
            .register(meterRegistry);

        this.duplicatesCounter = Counter.builder("alerts_duplicates_total")
            .description("Duplicate alerts skipped")
            .register(meterRegistry);

        this.blockedCounter = Counter.builder("ips_auto_blocked_total")
            .description("IPs auto-blocked due to threshold")
            .register(meterRegistry);

        this.telegramCounter = Counter.builder("telegram_notifications_total")
            .description("Telegram notifications sent")
            .register(meterRegistry);

        Gauge.builder("blocklist_size", blocklistService::getBlocklistSize)
            .description("Current blocklist size")
            .register(meterRegistry);
    }

    public void processAlert(Alert alert) {
        if (isDuplicate(alert)) {
            log.debug("Skipping duplicate alert: {}", alert.getAlertId());
            duplicatesCounter.increment();
            totalDuplicates.incrementAndGet();
            return;
        }

        markAsProcessed(alert);
        alertsCounter.increment();
        totalProcessed.incrementAndGet();

        updateStats(alert);

        if (alert.getThresholdExceeded() >= autoBlockThreshold) {
            blocklistService.addToBlocklist(alert.getSourceIp(), "ALERT:" + alert.getThreatType());
            blockedCounter.increment();
            ipsAutoBlocked.incrementAndGet();
            log.warn("Auto-blocked IP {} due to {} threshold exceeded",
                alert.getSourceIp(), alert.getThreatType());
        }

        telegramService.sendNotification(alert);
        telegramCounter.increment();
        webSocketService.sendAlert(alert);
        log.info("Alert processed: {} from {} with {} attempts",
            alert.getThreatType(), alert.getSourceIp(), alert.getThresholdExceeded());
    }

    private boolean isDuplicate(Alert alert) {
        return processedAlertIds.contains(alert.getAlertId());
    }

    private void markAsProcessed(Alert alert) {
        processedAlertIds.add(alert.getAlertId());
    }

    private void updateStats(Alert alert) {
        AlertStats stats = alertStats.computeIfAbsent(alert.getSourceIp(), k -> new AlertStats());
        stats.addAlert(alert);
    }

    public Map<String, AlertStats> getAlertStats() {
        return Map.copyOf(alertStats);
    }

    public long getTotalAlerts() {
        return totalProcessed.get();
    }

    public void cleanup() {
        long cutoff = Instant.now().toEpochMilli() - (deduplicationWindowSeconds * 1000L);
        processedAlertIds.removeIf(id -> id.hashCode() < cutoff);
    }

    public static class AlertStats {
        private int totalAlerts;
        private int ddosAlerts;
        private int bruteForceAlerts;
        private Instant lastAlertTime;

        public void addAlert(Alert alert) {
            totalAlerts++;
            lastAlertTime = Instant.now();

            if (alert.getThreatType() == ThreatType.DDOS_PATTERN) {
                ddosAlerts++;
            } else if (alert.getThreatType() == ThreatType.RATE_LIMIT_EXCEEDED) {
                bruteForceAlerts++;
            }
        }

        public int getTotalAlerts() { return totalAlerts; }
        public int getDdosAlerts() { return ddosAlerts; }
        public int getBruteForceAlerts() { return bruteForceAlerts; }
        public Instant getLastAlertTime() { return lastAlertTime; }
    }
}