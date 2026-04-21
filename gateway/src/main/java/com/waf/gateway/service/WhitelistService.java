package com.waf.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Service
@Slf4j
public class WhitelistService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${waf.whitelist.enabled:true}")
    private boolean whitelistEnabled;

    private static final String WHITELIST_IP_SET = "whitelist:ips";
    private static final String WHITELIST_PATH_SET = "whitelist:paths";
    private static final String WHITELIST_COUNTRY_SET = "whitelist:countries";
    private static final String WHITELIST_USER_AGENT_SET = "whitelist:user-agents";

    public WhitelistService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
        initializeDefaultWhitelist();
    }

    public boolean isIpWhitelisted(String ip) {
        if (!whitelistEnabled || ip == null) {
            return false;
        }

        try {
            Boolean isMember = redisTemplate.opsForSet().isMember(WHITELIST_IP_SET, ip);
            if (Boolean.TRUE.equals(isMember)) {
                log.debug("IP {} is whitelisted", ip);
                return true;
            }

            for (String cidr : getCidrWhitelist()) {
                if (ipInCidr(ip, cidr)) {
                    return true;
                }
            }
        } catch (Exception e) {
            log.warn("Error checking IP whitelist: {}", e.getMessage());
        }

        return false;
    }

    public boolean isPathWhitelisted(String path) {
        if (!whitelistEnabled || path == null) {
            return false;
        }

        try {
            Set<Object> paths = redisTemplate.opsForSet().members(WHITELIST_PATH_SET);
            
            if (paths != null) {
                for (Object pattern : paths) {
                    String patternStr = pattern.toString();
                    
                    if (patternStr.startsWith("regex:")) {
                        String regex = patternStr.substring(6);
                        if (Pattern.matches(regex, path)) {
                            return true;
                        }
                    } else if (patternStr.endsWith("*")) {
                        String prefix = patternStr.substring(0, patternStr.length() - 1);
                        if (path.startsWith(prefix)) {
                            return true;
                        }
                    } else if (path.equals(patternStr)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Error checking path whitelist: {}", e.getMessage());
        }

        return false;
    }

    public boolean isCountryWhitelisted(String countryCode) {
        if (!whitelistEnabled || countryCode == null) {
            return false;
        }

        try {
            return Boolean.TRUE.equals(
                redisTemplate.opsForSet().isMember(WHITELIST_COUNTRY_SET, countryCode)
            );
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isUserAgentWhitelisted(String userAgent) {
        if (!whitelistEnabled || userAgent == null) {
            return false;
        }

        try {
            String lowerUA = userAgent.toLowerCase();
            Set<Object> whitelisted = redisTemplate.opsForSet().members(WHITELIST_USER_AGENT_SET);
            
            if (whitelisted != null) {
                for (Object ua : whitelisted) {
                    if (lowerUA.contains(ua.toString().toLowerCase())) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Error checking user agent whitelist: {}", e.getMessage());
        }

        return false;
    }

    public void addIpToWhitelist(String ip) {
        addIpToWhitelist(ip, null);
    }

    public void addIpToWhitelist(String ip, Long ttlSeconds) {
        if (ip == null) {
            return;
        }

        try {
            redisTemplate.opsForSet().add(WHITELIST_IP_SET, ip);
            
            if (ttlSeconds != null && ttlSeconds > 0) {
                redisTemplate.expire(WHITELIST_IP_SET, ttlSeconds, TimeUnit.SECONDS);
                log.info("Added temporary whitelist IP: {} (TTL: {}s)", ip, ttlSeconds);
            } else {
                log.info("Added permanent whitelist IP: {}", ip);
            }
        } catch (Exception e) {
            log.error("Error adding IP to whitelist: {}", e.getMessage());
        }
    }

    public void addPathToWhitelist(String pathPattern) {
        if (pathPattern == null) {
            return;
        }

        try {
            redisTemplate.opsForSet().add(WHITELIST_PATH_SET, pathPattern);
            log.info("Added whitelist path: {}", pathPattern);
        } catch (Exception e) {
            log.error("Error adding path to whitelist: {}", e.getMessage());
        }
    }

    public void addCidrToWhitelist(String cidr) {
        if (cidr == null) {
            return;
        }

        try {
            String key = "whitelist:cidrs";
            redisTemplate.opsForSet().add(key, cidr);
            log.info("Added whitelist CIDR: {}", cidr);
        } catch (Exception e) {
            log.error("Error adding CIDR to whitelist: {}", e.getMessage());
        }
    }

    public void removeFromWhitelist(String ip) {
        if (ip == null) {
            return;
        }

        try {
            redisTemplate.opsForSet().remove(WHITELIST_IP_SET, ip);
            log.info("Removed from whitelist IP: {}", ip);
        } catch (Exception e) {
            log.error("Error removing IP from whitelist: {}", e.getMessage());
        }
    }

    public Set<Object> getWhitelistedIps() {
        try {
            return redisTemplate.opsForSet().members(WHITELIST_IP_SET);
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    public Set<Object> getWhitelistedPaths() {
        try {
            return redisTemplate.opsForSet().members(WHITELIST_PATH_SET);
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    public boolean isWhitelistEnabled() {
        return whitelistEnabled;
    }

    private void initializeDefaultWhitelist() {
        try {
            Long ipCount = redisTemplate.opsForSet().size(WHITELIST_IP_SET);
            if (ipCount == null || ipCount == 0) {
                redisTemplate.opsForSet().add(WHITELIST_IP_SET, "127.0.0.1", "localhost", "::1");
                redisTemplate.opsForSet().add(WHITELIST_PATH_SET, "/health", "/health/*", "/metrics");
                redisTemplate.opsForSet().add(WHITELIST_COUNTRY_SET);
                redisTemplate.opsForSet().add(WHITELIST_USER_AGENT_SET);
                log.info("Initialized default whitelist");
            }
        } catch (Exception e) {
            log.warn("Error initializing default whitelist: {}", e.getMessage());
        }
    }

    private Set<String> getCidrWhitelist() {
        try {
            Set<Object> cidrs = redisTemplate.opsForSet().members("whitelist:cidrs");
            if (cidrs == null) {
                return Collections.emptySet();
            }
            Set<String> result = new HashSet<>();
            for (Object cidr : cidrs) {
                result.add(cidr.toString());
            }
            return result;
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    private boolean ipInCidr(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/");
            String baseIp = parts[0];
            int prefixLen = parts.length > 1 ? Integer.parseInt(parts[1]) : 32;

            long ipLong = ipToLong(ip);
            long baseLong = ipToLong(baseIp);
            
            long mask;
            if (prefixLen == 0) {
                mask = 0;
            } else {
                int shift = 32 - prefixLen;
                if (shift >= 0) {
                    mask = 0xFFFFFFFFFFFFFFFFL << shift;
                } else {
                    mask = 0xFFFFFFFFFFFFFFFFL >>> (-shift);
                }
            }

            return (ipLong & mask) == (baseLong & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private long ipToLong(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return 0;
            }
            long result = 0;
            for (int i = 0; i < 4; i++) {
                result = (result << 8) + Integer.parseInt(parts[i]);
            }
            return result;
        } catch (Exception e) {
            return 0;
        }
    }

    public void setWhitelistEnabled(boolean enabled) {
        this.whitelistEnabled = enabled;
    }
}