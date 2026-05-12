package com.waf.alert.consumer;

import com.waf.alert.service.AlertService;
import com.waf.common.model.Alert;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AlertConsumer {

    private final AlertService alertService;

    public AlertConsumer(AlertService alertService) {
        this.alertService = alertService;
    }

    @KafkaListener(topics = "security.alerts", groupId = "alert-service")
    public void consumeAlert(Alert alert) {
        try {
            log.info("Received alert: {} from {} with {} attempts",
                alert.getThreatType(), alert.getSourceIp(), alert.getThresholdExceeded());
            alertService.processAlert(alert);
        } catch (Exception e) {
            log.error("Error processing alert: {}", e.getMessage(), e);
        }
    }
}