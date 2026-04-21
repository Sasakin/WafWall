package com.waf.gateway.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RateLimitService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${waf.rate-limit.window-seconds:60}")
    private int windowSizeSeconds;

    @Value("${waf.rate-limit.max-requests:100}")
    private int maxRequestsPerWindow;

    public RateLimitService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean isAllowed(String ip, String endpoint) {
        String key = String.format("rate_limit:%s:%s", ip, endpoint);
        long now = System.currentTimeMillis();
        long windowStart = now - (windowSizeSeconds * 1000L);

        redisTemplate.opsForZSet().removeRangeByScore(key, 0, windowStart);

        Long count = redisTemplate.opsForZSet().zCard(key);

        if (count != null && count >= maxRequestsPerWindow) {
            return false;
        }

        redisTemplate.opsForZSet().add(key, String.valueOf(now), now);
        redisTemplate.expire(key, windowSizeSeconds, TimeUnit.SECONDS);

        return true;
    }
}