package com.waf.common.repository;

public interface RateLimitRepository {

    boolean isAllowed(String key, int limit, int windowSeconds);

    void recordRequest(String key, int windowSeconds);
}