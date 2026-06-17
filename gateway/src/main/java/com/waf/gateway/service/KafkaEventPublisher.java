package com.waf.gateway.service;

import com.waf.common.model.SecurityEvent;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

@Component
public class KafkaEventPublisher implements EventPublisher {

    private static final String TOPIC = "security.events";

    private final KafkaTemplate<String, SecurityEvent> kafkaTemplate;

    public KafkaEventPublisher(KafkaTemplate<String, SecurityEvent> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @Override
    public void publish(SecurityEvent event) {
        // eventId and timestamp already set by caller (WafService)
        CompletableFuture<SendResult<String, SecurityEvent>> future =
            kafkaTemplate.send(TOPIC, event.getSourceIp(), event);

        future.whenComplete((result, ex) -> {
            if (ex != null) {
                System.err.println("Failed to send security event: " + ex.getMessage());
            }
        });
    }
}