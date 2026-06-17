package com.waf.gateway.service;

import com.waf.common.model.ThreatType;
import com.waf.gateway.filter.FilterResult;
import com.waf.gateway.filter.SecurityFilter;
import com.waf.gateway.util.IpUtil;
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
        // === OPTIMIZATION 1: Skip if already checked in WafFilter ===
        if (Boolean.TRUE.equals(request.getAttribute("waf.ratelimit.checked"))) {
            return pass();
        }
        String clientIp = IpUtil.getClientIp(request);
        String path = request.getRequestURI();

        if (!rateLimitService.isAllowed(clientIp, path)) {
            return block("Rate limit exceeded for IP: " + clientIp);
        }
        return pass();
    }
}