package com.waf.gateway.filter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SecurityFilterChain {

    private final List<SecurityFilter> filters;

    public SecurityFilterChain(List<SecurityFilter> filters) {
        this.filters = filters;
    }

    public FilterResult execute(HttpServletRequest request) {
        for (SecurityFilter filter : filters) {
            FilterResult result = filter.check(request);
            if (result.isBlocked()) {
                return result;
            }
        }
        return FilterResult.pass();
    }
}