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
public class XssFilter implements SecurityFilter {

    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)(<script|javascript:|onerror=|onload=|alert\\(|eval\\(|document\\.|cookie\\.|" +
            "iframe|<svg|onmouseover=|onfocus=|onblur=)"
    );

    @Override
    public ThreatType getThreatType() {
        return ThreatType.XSS_ATTACK;
    }

    @Override
    public FilterResult check(HttpServletRequest request) {
        if (containsXss(request)) {
            return block("XSS pattern detected");
        }
        return pass();
    }

    public boolean containsXss(HttpServletRequest request) {
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
            return XSS_PATTERN.matcher(decoded).find();
        } catch (Exception e) {
            return XSS_PATTERN.matcher(input).find();
        }
    }

    private String getRequestBody(HttpServletRequest request) {
        return null;
    }
}