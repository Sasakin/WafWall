package com.waf.processor.consumer;

import com.waf.common.model.Alert;
import com.waf.common.model.SecurityEvent;
import com.waf.processor.service.AnomalyDetectionService;
import com.waf.processor.service.ClickHouseWriterService;
import com.waf.processor.service.EventAggregationService;
import com.waf.processor.service.GeoIpEnrichmentService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class SecurityEventConsumer {

    private static final String ALERT_TOPIC = "security.alerts";

    private final ClickHouseWriterService clickHouseWriter;
    private final EventAggregationService aggregationService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final GeoIpEnrichmentService geoIpEnrichment;
    private final KafkaTemplate<String, Alert> alertKafkaTemplate;

    @Value("${processor.batch-size:100}")
    private int batchSize;

    @Value("${processor.batch-timeout-ms:5000}")
    private long batchTimeout;

    private final Map<String, List<SecurityEvent>> eventBuffer = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public SecurityEventConsumer(
            ClickHouseWriterService clickHouseWriter,
            EventAggregationService aggregationService,
            AnomalyDetectionService anomalyDetectionService,
            GeoIpEnrichmentService geoIpEnrichment,
            KafkaTemplate<String, Alert> alertKafkaTemplate) {
        this.clickHouseWriter = clickHouseWriter;
        this.aggregationService = aggregationService;
        this.anomalyDetectionService = anomalyDetectionService;
        this.geoIpEnrichment = geoIpEnrichment;
        this.alertKafkaTemplate = alertKafkaTemplate;
    }

    @jakarta.annotation.PostConstruct
    public void init() {
        startBatchProcessor();
    }

    @KafkaListener(topics = "security.events", groupId = "stream-processor")
    public void consumeEvent(SecurityEvent event) {
        try {
            enrichEvent(event);

            aggregationService.processEvent(event);

            Optional<AnomalyDetectionService.Anomaly> anomaly = anomalyDetectionService.analyzeEvent(event);
            if (anomaly.isPresent()) {
                sendAlert(anomaly.get());
            }

            List<SecurityEvent> buffer = eventBuffer.computeIfAbsent(
                event.getSourceIp(), k -> new ArrayList<>());
            synchronized (buffer) {
                buffer.add(event);
                if (buffer.size() >= batchSize) {
                    flushBuffer(event.getSourceIp());
                }
            }
        } catch (Exception e) {
            log.error("Error processing event: {}", e.getMessage(), e);
        }
    }

    private void enrichEvent(SecurityEvent event) {
        if (event.getCountryCode() == null || event.getCountryCode().isEmpty()) {
            event.setCountryCode(geoIpEnrichment.getCountryCode(event.getSourceIp()));
        }

        if (event.getTimestamp() == null) {
            event.setTimestamp(Instant.now());
        }

        if (event.getEventId() == null || event.getEventId().isEmpty()) {
            event.setEventId(UUID.randomUUID().toString());
        }
    }

    private void sendAlert(AnomalyDetectionService.Anomaly anomaly) {
        Alert alert = Alert.builder()
            .alertId(UUID.randomUUID().toString())
            .sourceIp(anomaly.getSourceIp())
            .threatType(anomaly.getThreatType())
            .thresholdExceeded((int) anomaly.getCount())
            .timestamp(Instant.now())
            .message(String.format("Detected %s attack from IP %s with %d attempts",
                anomaly.getThreatType(), anomaly.getSourceIp(), anomaly.getCount()))
            .build();

        try {
            alertKafkaTemplate.send(ALERT_TOPIC, alert.getSourceIp(), alert);
            log.warn("Alert sent: {}", alert.getMessage());
        } catch (Exception e) {
            log.error("Failed to send alert: {}", e.getMessage());
        }
    }

    private void startBatchProcessor() {
        scheduler.scheduleAtFixedRate(() -> {
            for (String ip : eventBuffer.keySet()) {
                flushBuffer(ip);
            }
        }, batchTimeout, batchTimeout, TimeUnit.MILLISECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            aggregationService.getCurrentAggregates();
        }, 60, 60, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            anomalyDetectionService.cleanup();
        }, 300, 300, TimeUnit.SECONDS);
    }

    private void flushBuffer(String ip) {
        List<SecurityEvent> buffer = eventBuffer.remove(ip);
        if (buffer != null && !buffer.isEmpty()) {
            clickHouseWriter.writeEventsBatch(buffer);
            log.debug("Flushed {} events for IP {}", buffer.size(), ip);
        }
    }

    public void shutdown() {
        scheduler.shutdown();
        for (String ip : eventBuffer.keySet()) {
            flushBuffer(ip);
        }
    }
}