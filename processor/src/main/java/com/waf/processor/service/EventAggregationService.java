package com.waf.processor.service;

import com.waf.common.model.SecurityEvent;
import com.waf.common.model.ThreatType;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;

@Service
public class EventAggregationService {

    private static final long WINDOW_SIZE_MS = 60_000L;
    private static final int THRESHOLD_DDOS = 50;
    private static final int THRESHOLD_BRUTE_FORCE = 10;

    private final Map<String, AggregateWindow> ipAggregates = new ConcurrentHashMap<>();

    public void processEvent(SecurityEvent event) {
        String key = event.getSourceIp();
        long windowStart = getWindowStart(event.getTimestamp());

        AggregateWindow window = ipAggregates.computeIfAbsent(key, k -> new AggregateWindow());
        window.addEvent(event, windowStart);

        cleanupOldWindows(window);
    }

    public List<String> detectDdosAttack(String ip) {
        AggregateWindow window = ipAggregates.get(ip);
        if (window == null) {
            return Collections.emptyList();
        }

        long windowStart = getWindowStart(Instant.now());
        List<SecurityEvent> events = window.getEvents(windowStart);

        if (events.size() >= THRESHOLD_DDOS) {
            boolean mostlyBlocked = events.stream()
                .filter(SecurityEvent::getIsBlocked)
                .count() > (events.size() * 0.8);

            if (mostlyBlocked) {
                return events.stream()
                    .map(SecurityEvent::getSourceIp)
                    .distinct()
                    .collect(Collectors.toList());
            }
        }
        return Collections.emptyList();
    }

    public Optional<BruteForceAttempt> detectBruteForce(String ip) {
        AggregateWindow window = ipAggregates.get(ip);
        if (window == null) {
            return Optional.empty();
        }

        long windowStart = getWindowStart(Instant.now());
        List<SecurityEvent> events = window.getEvents(windowStart);

        Map<String, Long> pathCounts = events.stream()
            .collect(Collectors.groupingBy(SecurityEvent::getRequestPath, Collectors.counting()));

        for (Map.Entry<String, Long> entry : pathCounts.entrySet()) {
            if (entry.getValue() >= THRESHOLD_BRUTE_FORCE) {
                return Optional.of(new BruteForceAttempt(ip, entry.getKey(), entry.getValue()));
            }
        }
        return Optional.empty();
    }

    public Map<String, AggregationResult> getCurrentAggregates() {
        long windowStart = getWindowStart(Instant.now());
        Map<String, AggregationResult> results = new HashMap<>();

        for (Map.Entry<String, AggregateWindow> entry : ipAggregates.entrySet()) {
            List<SecurityEvent> events = entry.getValue().getEvents(windowStart);
            if (!events.isEmpty()) {
                long blocked = events.stream().filter(SecurityEvent::getIsBlocked).count();
                results.put(entry.getKey(), new AggregationResult(events.size(), blocked, blocked > 0));
            }
        }
        return results;
    }

    private long getWindowStart(Instant timestamp) {
        return (timestamp.toEpochMilli() / WINDOW_SIZE_MS) * WINDOW_SIZE_MS;
    }

    private void cleanupOldWindows(AggregateWindow window) {
        long cutoff = Instant.now().toEpochMilli() - (WINDOW_SIZE_MS * 2);
        window.cleanup(cutoff);
    }

    private static class AggregateWindow {
        private final ConcurrentLinkedQueue<SecurityEvent> events = new ConcurrentLinkedQueue<>();

        public void addEvent(SecurityEvent event, long windowStart) {
            events.add(event);
        }

        public List<SecurityEvent> getEvents(long windowStart) {
            return events.stream()
                .filter(e -> e.getTimestamp().toEpochMilli() >= windowStart)
                .collect(Collectors.toList());
        }

        public void cleanup(long cutoff) {
            events.removeIf(e -> e.getTimestamp().toEpochMilli() < cutoff);
        }
    }

    public static class BruteForceAttempt {
        private final String ip;
        private final String path;
        private final long attempts;

        public BruteForceAttempt(String ip, String path, long attempts) {
            this.ip = ip;
            this.path = path;
            this.attempts = attempts;
        }

        public String getIp() { return ip; }
        public String getPath() { return path; }
        public long getAttempts() { return attempts; }
    }

    public static class AggregationResult {
        private final long totalRequests;
        private final long blockedRequests;
        private final boolean hasThreats;

        public AggregationResult(long total, long blocked, boolean threats) {
            this.totalRequests = total;
            this.blockedRequests = blocked;
            this.hasThreats = threats;
        }

        public long getTotalRequests() { return totalRequests; }
        public long getBlockedRequests() { return blockedRequests; }
        public boolean hasThreats() { return hasThreats; }
    }
}