package com.waf.processor.service;

import com.waf.common.model.SecurityEvent;
import com.waf.common.model.ThreatType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Optional;

@Service
public class AnomalyDetectionService {

    @Value("${anomaly.detection.ddos-threshold:50}")
    private int ddosThreshold;

    @Value("${anomaly.detection.brute-force-threshold:10}")
    private int bruteForceThreshold;

    @Value("${anomaly.detection.new-threat-window-seconds:300}")
    private int newThreatWindowSeconds;

    private final Map<String, ThreatCounter> threatCounters = new ConcurrentHashMap<>();

    public Optional<Anomaly> analyzeEvent(SecurityEvent event) {
        if (!event.getIsBlocked()) {
            return Optional.empty();
        }

        String ip = event.getSourceIp();
        ThreatType threatType = event.getThreatType();

        ThreatCounter counter = threatCounters.computeIfAbsent(ip, k -> new ThreatCounter());
        counter.increment(threatType);

        if (counter.getCount(threatType) >= getThreshold(threatType)) {
            Anomaly anomaly = Anomaly.builder()
                .sourceIp(ip)
                .threatType(threatType)
                .count(counter.getCount(threatType))
                .windowStart(counter.getWindowStart(threatType))
                .timestamp(Instant.now())
                .build();

            counter.reset(threatType);
            return Optional.of(anomaly);
        }

        return Optional.empty();
    }

    public void cleanup() {
        long cutoff = Instant.now().toEpochMilli() - (newThreatWindowSeconds * 1000L);
        threatCounters.entrySet().removeIf(entry -> entry.getValue().isExpired(cutoff));
    }

    private int getThreshold(ThreatType threatType) {
        return switch (threatType) {
            case DDOS_PATTERN -> ddosThreshold;
            case BOT_DETECTED -> bruteForceThreshold * 2;
            default -> bruteForceThreshold;
        };
    }

    private static class ThreatCounter {
        private final Map<ThreatType, CounterEntry> counters = new ConcurrentHashMap<>();

        public void increment(ThreatType threatType) {
            CounterEntry entry = counters.computeIfAbsent(threatType, k -> new CounterEntry());
            entry.increment();
        }

        public long getCount(ThreatType threatType) {
            CounterEntry entry = counters.get(threatType);
            return entry != null ? entry.count : 0;
        }

        public long getWindowStart(ThreatType threatType) {
            CounterEntry entry = counters.get(threatType);
            return entry != null ? entry.windowStart : 0;
        }

        public void reset(ThreatType threatType) {
            counters.remove(threatType);
        }

        public boolean isExpired(long cutoff) {
            return counters.values().stream().allMatch(e -> e.windowStart < cutoff);
        }

        private static class CounterEntry {
            long count = 1;
            long windowStart = Instant.now().toEpochMilli();

            void increment() {
                count++;
            }
        }
    }

    public static class Anomaly {
        private final String sourceIp;
        private final ThreatType threatType;
        private final long count;
        private final long windowStart;
        private final Instant timestamp;

        private Anomaly(Builder builder) {
            this.sourceIp = builder.sourceIp;
            this.threatType = builder.threatType;
            this.count = builder.count;
            this.windowStart = builder.windowStart;
            this.timestamp = builder.timestamp;
        }

        public static Builder builder() {
            return new Builder();
        }

        public String getSourceIp() { return sourceIp; }
        public ThreatType getThreatType() { return threatType; }
        public long getCount() { return count; }
        public long getWindowStart() { return windowStart; }
        public Instant getTimestamp() { return timestamp; }

        public static class Builder {
            private String sourceIp;
            private ThreatType threatType;
            private long count;
            private long windowStart;
            private Instant timestamp;

            public Builder sourceIp(String sourceIp) {
                this.sourceIp = sourceIp;
                return this;
            }

            public Builder threatType(ThreatType threatType) {
                this.threatType = threatType;
                return this;
            }

            public Builder count(long count) {
                this.count = count;
                return this;
            }

            public Builder windowStart(long windowStart) {
                this.windowStart = windowStart;
                return this;
            }

            public Builder timestamp(Instant timestamp) {
                this.timestamp = timestamp;
                return this;
            }

            public Anomaly build() {
                return new Anomaly(this);
            }
        }
    }
}