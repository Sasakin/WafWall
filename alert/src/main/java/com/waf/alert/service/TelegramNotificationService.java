package com.waf.alert.service;

import com.waf.common.model.Alert;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
@Slf4j
public class TelegramNotificationService {

    @Value("${telegram.bot-token:}")
    private String botToken;

    @Value("${telegram.chat-id:}")
    private String chatId;

    @Value("${telegram.enabled:false}")
    private boolean enabled;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    public void sendNotification(Alert alert) {
        if (!enabled || botToken.isEmpty() || chatId.isEmpty()) {
            log.debug("Telegram notifications disabled or not configured");
            return;
        }

        String message = formatMessage(alert);

        try {
            sendTelegramMessage(message);
            log.info("Telegram notification sent for alert: {}", alert.getAlertId());
        } catch (Exception e) {
            log.error("Failed to send Telegram notification: {}", e.getMessage());
        }
    }

    private void sendTelegramMessage(String message) throws Exception {
        String url = String.format("https://api.telegram.org/bot%s/sendMessage", botToken);
        String json = String.format(
            "{\"chat_id\": \"%s\", \"text\": \"%s\", \"parse_mode\": \"Markdown\"}",
            chatId, escapeMarkdown(message)
        );

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Telegram API error: " + response.statusCode());
        }
    }

    private String formatMessage(Alert alert) {
        return String.format("""
            🔴 *WAF Alert*

            *Type:* %s
            *IP:* `%s`
            *Attempts:* %d
            *Time:* %s

            %s
            """,
            alert.getThreatType(),
            alert.getSourceIp(),
            alert.getThresholdExceeded(),
            alert.getTimestamp(),
            alert.getMessage() != null ? alert.getMessage() : ""
        );
    }

    private String escapeMarkdown(String text) {
        return text.replace("_", "\\_")
            .replace("*", "\\*")
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("`", "\\`");
    }
}