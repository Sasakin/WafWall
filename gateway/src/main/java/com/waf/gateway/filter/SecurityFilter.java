package com.waf.gateway.filter;

import com.waf.common.model.ThreatType;
import jakarta.servlet.http.HttpServletRequest;

public interface SecurityFilter {

    FilterResult check(HttpServletRequest request);

    ThreatType getThreatType();

    default FilterResult pass() {
        return FilterResult.pass();
    }

    default FilterResult block(String reason) {
        return FilterResult.block(getThreatType(), reason);
    }

    default FilterResult block(ThreatType threatType, String reason) {
        return FilterResult.block(threatType, reason);
    }
}