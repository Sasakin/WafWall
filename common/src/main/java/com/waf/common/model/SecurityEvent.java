package com.waf.common.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {
    private String eventId;
    private Instant timestamp;
    private String sourceIp;
    private String userAgent;
    private String requestPath;
    private String requestMethod;
    private ThreatType threatType;
    private Integer threatScore;
    private Boolean isBlocked;
    private Integer responseTimeMs;
    private String countryCode;
}