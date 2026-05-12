package com.waf.alert.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class BlocklistService {

    private static final String BLOCKLIST_PREFIX = "blocked:ip:";
    private static final String BLOCKLIST_SET = "blocklist:ips";

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${blocklist.default-ttl-seconds:3600}")
    private long defaultTtlSeconds;

    public BlocklistService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void addToBlocklist(String ip, String reason) {
        String key = BLOCKLIST_PREFIX + ip;
        String value = reason != null ? reason : "manual";

        redisTemplate.opsForValue().set(key, value, defaultTtlSeconds, TimeUnit.SECONDS);
        redisTemplate.opsForSet().add(BLOCKLIST_SET, ip);

        log.info("Added {} to blocklist, reason: {}", ip, value);
    }

    public void addToBlocklist(String ip, String reason, long ttlSeconds) {
        String key = BLOCKLIST_PREFIX + ip;
        String value = reason != null ? reason : "manual";

        redisTemplate.opsForValue().set(key, value, ttlSeconds, TimeUnit.SECONDS);
        redisTemplate.opsForSet().add(BLOCKLIST_SET, ip);

        log.info("Added {} to blocklist for {} seconds, reason: {}", ip, ttlSeconds, value);
    }

    public boolean isBlocked(String ip) {
        String key = BLOCKLIST_PREFIX + ip;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    public void removeFromBlocklist(String ip) {
        String key = BLOCKLIST_PREFIX + ip;
        redisTemplate.delete(key);
        redisTemplate.opsForSet().remove(BLOCKLIST_SET, ip);

        log.info("Removed {} from blocklist", ip);
    }

    public Set<Object> getBlockedIps() {
        return redisTemplate.opsForSet().members(BLOCKLIST_SET);
    }

    public Long getBlocklistSize() {
        return redisTemplate.opsForSet().size(BLOCKLIST_SET);
    }

    public String getBlockReason(String ip) {
        String key = BLOCKLIST_PREFIX + ip;
        Object reason = redisTemplate.opsForValue().get(key);
        return reason != null ? reason.toString() : null;
    }

    public boolean extendBlock(String ip, long additionalSeconds) {
        String key = BLOCKLIST_PREFIX + ip;
        if (isBlocked(ip)) {
            Long newTtl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
            if (newTtl > 0) {
                redisTemplate.expire(key, newTtl + additionalSeconds, TimeUnit.SECONDS);
                return true;
            }
        }
        return false;
    }

    public void clearBlocklist() {
        Set<Object> ips = getBlockedIps();
        for (Object ip : ips) {
            removeFromBlocklist(ip.toString());
        }
        log.info("Cleared blocklist, removed {} IPs", ips.size());
    }
}