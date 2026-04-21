package com.waf.gateway.service;

import com.waf.common.model.ThreatType;
import com.waf.gateway.filter.FilterResult;
import com.waf.gateway.filter.SecurityFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class RateLimitFilter implements SecurityFilter {

    private final RateLimitService rateLimitService;

    public RateLimitFilter(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    @Override
    public ThreatType getThreatType() {
        return ThreatType.RATE_LIMIT_EXCEEDED;
    }

    @Override
    public FilterResult check(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        String path = request.getRequestURI();

        if (!rateLimitService.isAllowed(clientIp, path)) {
            return block("Rate limit exceeded for IP: " + clientIp);
        }
        return pass();
    }
}