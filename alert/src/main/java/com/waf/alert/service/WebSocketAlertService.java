package com.waf.alert.service;

import com.waf.common.model.Alert;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class WebSocketAlertService {

    private final SimpMessagingTemplate messagingTemplate;

    public void sendAlert(Alert alert) {
        try {
            messagingTemplate.convertAndSend("/topic/alerts", alert);
            log.debug("Alert sent via WebSocket: {}", alert.getAlertId());
        } catch (Exception e) {
            log.error("Failed to send WebSocket alert: {}", e.getMessage());
        }
    }

    public void sendBlockedIpNotification(String ip, String reason) {
        try {
            var notification = new java.util.HashMap<String, Object>();
            notification.put("type", "BLOCKED_IP");
            notification.put("ip", ip);
            notification.put("reason", reason);
            notification.put("timestamp", System.currentTimeMillis());
            messagingTemplate.convertAndSend("/topic/alerts", notification);
        } catch (Exception e) {
            log.error("Failed to send blocked IP notification: {}", e.getMessage());
        }
    }
}