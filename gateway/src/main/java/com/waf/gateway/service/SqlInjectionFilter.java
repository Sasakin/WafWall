package com.waf.gateway.service;

import com.waf.common.model.ThreatType;
import com.waf.gateway.filter.FilterResult;
import com.waf.gateway.filter.SecurityFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

@Component
public class SqlInjectionFilter implements SecurityFilter {

    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(?i)(union\\s+select|drop\\s+table|insert\\s+into|" +
            "delete\\s+from|update\\s+.*\\s+set|--|/\\*|\\*/|" +
            "';\\s*--|\\bor\\s+1\\s*=\\s*1|\\band\\s+1\\s*=\s*1)"
    );

    @Override
    public ThreatType getThreatType() {
        return ThreatType.SQL_INJECTION;
    }

    @Override
    public FilterResult check(HttpServletRequest request) {
        if (containsSqlInjection(request)) {
            return block("SQL injection pattern detected");
        }
        return pass();
    }

    public boolean containsSqlInjection(HttpServletRequest request) {
        String queryString = request.getQueryString();
        if (checkPattern(queryString)) {
            return true;
        }

        String body = getRequestBody(request);
        return checkPattern(body);
    }

    private boolean checkPattern(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        try {
            String decoded = URLDecoder.decode(input, StandardCharsets.UTF_8);
            return SQLI_PATTERN.matcher(decoded).find();
        } catch (Exception e) {
            return SQLI_PATTERN.matcher(input).find();
        }
    }

    private String getRequestBody(HttpServletRequest request) {
        return null;
    }
}