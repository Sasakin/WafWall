package com.waf.gateway.service;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class RateLimitService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitService.class);
    private static final int LOCAL_THRESHOLD = 50;

    private final LoadingCache<String, AtomicLong> localCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofSeconds(60))
            .build(key -> new AtomicLong(0));

    private final StringRedisTemplate stringRedisTemplate;
    private final DefaultRedisScript rateLimitScript;

    @Value("${waf.rate-limit.window-seconds:60}")
    private int windowSizeSeconds;

    @Value("${waf.rate-limit.max-requests:100}")
    private int maxRequestsPerWindow;

    public RateLimitService(StringRedisTemplate stringRedisTemplate,
                            @Qualifier("rateLimitScript") DefaultRedisScript rateLimitScript) {
        this.stringRedisTemplate = stringRedisTemplate;
        this.rateLimitScript = rateLimitScript;
    }

    @CircuitBreaker(name = "redisBackend", fallbackMethod = "fallbackCheck")
    public boolean isAllowed(String ip, String endpoint) {
        String key = "rate_limit:" + ip + ":" + endpoint;
        long now = System.currentTimeMillis();
        long windowStart = now - (windowSizeSeconds * 1000L);

        AtomicLong local = localCache.get(key);
        if (local.get() >= LOCAL_THRESHOLD) {
            return false;
        }

        // Single Lua script call replaces 4 separate Redis commands:
        // ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE
        Object raw = stringRedisTemplate.execute(
                rateLimitScript,
                Collections.singletonList(key),
                String.valueOf(now),
                String.valueOf(windowStart),
                String.valueOf(maxRequestsPerWindow),
                String.valueOf(windowSizeSeconds)
        );

        if (!(raw instanceof List) || ((List) raw).size() < 2) {
            log.warn("Lua script returned null or unexpected result for key={}", key);
            return false;
        }

        List result = (List) raw;

        long redisCount = Long.parseLong(result.get(0).toString());
        boolean allowed = Integer.parseInt(result.get(1).toString()) == 1;

        local.set(redisCount);
        if (allowed) {
            local.incrementAndGet();
        }

        return allowed;
    }

    public boolean fallbackCheck(String ip, String endpoint, Throwable t) {
        log.warn("Redis unavailable, using local-only mode: {}", t.getMessage());
        String key = "rate_limit:" + ip + ":" + endpoint;
        AtomicLong local = localCache.get(key);
        if (local.get() >= LOCAL_THRESHOLD) {
            return false;
        }
        return local.incrementAndGet() < maxRequestsPerWindow;
    }
}
