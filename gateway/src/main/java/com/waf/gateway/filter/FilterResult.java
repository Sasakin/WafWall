package com.waf.gateway.filter;

import com.waf.common.model.ThreatType;

public class FilterResult {

    private final boolean blocked;
    private final boolean passed;
    private final ThreatType threatType;
    private final String reason;

    private FilterResult(boolean blocked, boolean passed, ThreatType threatType, String reason) {
        this.blocked = blocked;
        this.passed = passed;
        this.threatType = threatType;
        this.reason = reason;
    }

    public static FilterResult pass() {
        return new FilterResult(false, true, null, null);
    }

    public static FilterResult block(ThreatType threatType, String reason) {
        return new FilterResult(true, false, threatType, reason);
    }

    public boolean isBlocked() {
        return blocked;
    }

    public boolean isPassed() {
        return passed;
    }

    public ThreatType getThreatType() {
        return threatType;
    }

    public String getReason() {
        return reason;
    }
}