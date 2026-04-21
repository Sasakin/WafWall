package com.waf.gateway.filter;

import com.waf.common.model.ThreatType;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class FilterRegistry {

    private final Map<ThreatType, SecurityFilter> filters = new HashMap<>();

    public void register(ThreatType threatType, SecurityFilter filter) {
        filters.put(threatType, filter);
    }

    public Optional<SecurityFilter> get(ThreatType threatType) {
        return Optional.ofNullable(filters.get(threatType));
    }

    public boolean hasFilter(ThreatType threatType) {
        return filters.containsKey(threatType);
    }
}