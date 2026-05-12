package com.waf.gateway.service;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class RateLimitService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitService.class);
    private static final int LOCAL_THRESHOLD = 50;

    private final LoadingCache<String, AtomicLong> localCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofSeconds(60))
            .build(key -> new AtomicLong(0));

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${waf.rate-limit.window-seconds:60}")
    private int windowSizeSeconds;

    @Value("${waf.rate-limit.max-requests:100}")
    private int maxRequestsPerWindow;

    public RateLimitService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @CircuitBreaker(name = "redisBackend", fallbackMethod = "fallbackCheck")
    public boolean isAllowed(String ip, String endpoint) {
        String key = formatKey(ip, endpoint);
        long now = System.currentTimeMillis();
        long windowStart = now - (windowSizeSeconds * 1000L);

        AtomicLong local = localCache.get(key);
        if (local.get() >= LOCAL_THRESHOLD) {
            return false;
        }

        redisTemplate.opsForZSet().removeRangeByScore(key, 0, windowStart);
        Long redisCount = redisTemplate.opsForZSet().zCard(key);

        if (redisCount != null) {
            local.set(redisCount.intValue());
        }

        if (redisCount != null && redisCount >= maxRequestsPerWindow) {
            return false;
        }

        redisTemplate.opsForZSet().add(key, String.valueOf(now), now);
        redisTemplate.expire(key, windowSizeSeconds, TimeUnit.SECONDS);

        local.incrementAndGet();
        return true;
    }

    public boolean fallbackCheck(String ip, String endpoint, Throwable t) {
        log.warn("Redis unavailable, using local-only mode: {}", t.getMessage());
        String key = formatKey(ip, endpoint);
        AtomicLong local = localCache.get(key);
        if (local.get() >= LOCAL_THRESHOLD) {
            return false;
        }
        return local.incrementAndGet() < maxRequestsPerWindow;
    }

    private String formatKey(String ip, String endpoint) {
        return String.format("rate_limit:%s:%s", ip, endpoint);
    }
}