package com.waf.common.model;

public enum ThreatType {
    SQL_INJECTION,
    XSS_ATTACK,
    BOT_DETECTED,
    DDOS_PATTERN,
    RATE_LIMIT_EXCEEDED,
    UNKNOWN
}