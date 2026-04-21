package com.waf.gateway.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class MetricsService {

    private final MeterRegistry registry;

    // Request counters
    private final Counter requestsTotal;
    private final Counter requestsBlocked;
    private final Counter requestsAllowed;

    // By threat type
    private final Counter sqlInjectionBlocked;
    private final Counter xssBlocked;
    private final Counter botBlocked;
    private final Counter rateLimitBlocked;

    // Latency
    private final Timer requestLatency;

    // Gauge metrics
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final AtomicLong lastBlockedIpCount = new AtomicLong(0);

    public MetricsService(MeterRegistry registry) {
        this.registry = registry;

        // Total requests
        this.requestsTotal = Counter.builder("waf_requests_total")
            .description("Total WAF requests processed")
            .register(registry);

        this.requestsBlocked = Counter.builder("waf_requests_blocked_total")
            .description("Total blocked requests")
            .register(registry);

        this.requestsAllowed = Counter.builder("waf_requests_allowed_total")
            .description("Total allowed requests")
            .register(registry);

        // By threat type
        this.sqlInjectionBlocked = Counter.builder("waf_blocked_total")
            .tag("threat_type", "sql_injection")
            .description("SQL injection blocked")
            .register(registry);

        this.xssBlocked = Counter.builder("waf_blocked_total")
            .tag("threat_type", "xss")
            .description("XSS blocked")
            .register(registry);

        this.botBlocked = Counter.builder("waf_blocked_total")
            .tag("threat_type", "bot")
            .description("Bot detected")
            .register(registry);

        this.rateLimitBlocked = Counter.builder("waf_blocked_total")
            .tag("threat_type", "rate_limit")
            .description("Rate limit exceeded")
            .register(registry);

        // Latency
        this.requestLatency = Timer.builder("waf_request_duration_seconds")
            .description("WAF request processing duration")
            .register(registry);

        // Gauge metrics
        Gauge.builder("waf_active_connections", activeConnections, AtomicInteger::get)
            .description("Active connections")
            .register(registry);

        Gauge.builder("waf_blocked_ips_count", lastBlockedIpCount, AtomicLong::get)
            .description("Number of blocked IPs")
            .register(registry);
    }

    public void recordRequest() {
        requestsTotal.increment();
    }

    public void recordBlocked(String threatType) {
        requestsBlocked.increment();

        switch (threatType) {
            case "SQL_INJECTION" -> sqlInjectionBlocked.increment();
            case "XSS_ATTACK" -> xssBlocked.increment();
            case "BOT_DETECTED" -> botBlocked.increment();
            case "RATE_LIMIT_EXCEEDED" -> rateLimitBlocked.increment();
            default -> requestsBlocked.increment();
        }
    }

    public void recordAllowed() {
        requestsAllowed.increment();
    }

    public void recordLatency(long durationMs) {
        requestLatency.record(durationMs, TimeUnit.MILLISECONDS);
    }

    public void updateActiveConnections(int count) {
        activeConnections.set(count);
    }

    public void updateBlockedIpCount(long count) {
        lastBlockedIpCount.set(count);
    }

    public Timer.Sample startTimer() {
        return Timer.start(registry);
    }

    public void stopTimer(Timer.Sample sample) {
        sample.stop(requestLatency);
    }
}