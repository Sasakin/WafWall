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
public class Alert {
    private String alertId;
    private String sourceIp;
    private ThreatType threatType;
    private Integer thresholdExceeded;
    private Instant timestamp;
    private String message;
}