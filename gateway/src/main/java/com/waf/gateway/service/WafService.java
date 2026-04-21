package com.waf.gateway.service;

import com.waf.common.model.SecurityEvent;
import com.waf.common.model.ThreatType;
import com.waf.gateway.filter.SecurityFilterChain;
import com.waf.gateway.filter.FilterResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class WafService {

    private final SecurityFilterChain filterChain;
    private final EventPublisher eventPublisher;

    public WafService(SecurityFilterChain filterChain, EventPublisher eventPublisher) {
        this.filterChain = filterChain;
        this.eventPublisher = eventPublisher;
    }

    public void processRequest(String clientIp, String path, String userAgent,
                           HttpServletRequest request, HttpServletResponse response) {
        long startTime = System.currentTimeMillis();

        FilterResult filterResult = filterChain.execute(request);

        if (filterResult.isBlocked()) {
            blockRequest(clientIp, path, userAgent, filterResult.getThreatType(), startTime, response);
            return;
        }

        eventPublisher.publish(buildEvent(clientIp, path, userAgent, ThreatType.UNKNOWN, false, startTime));
    }

    private void blockRequest(String clientIp, String path, String userAgent,
                            ThreatType threatType, long startTime, HttpServletResponse response) {
        response.setStatus(403);
        eventPublisher.publish(buildEvent(clientIp, path, userAgent, threatType, true, startTime));
    }

    private SecurityEvent buildEvent(String clientIp, String path, String userAgent,
                                    ThreatType threatType, boolean isBlocked, long startTime) {
        return SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .sourceIp(clientIp)
                .userAgent(userAgent)
                .requestPath(path)
                .threatType(threatType)
                .isBlocked(isBlocked)
                .responseTimeMs((int) (System.currentTimeMillis() - startTime))
                .build();
    }
}