package com.waf.gateway.filter;

import com.waf.gateway.service.RateLimitService;
import com.waf.gateway.service.WafService;
import com.waf.gateway.util.IpUtil;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(1)
public class WafFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(WafFilter.class);
    private final WafService wafService;
    private final RateLimitService rateLimitService;

    public WafFilter(WafService wafService, RateLimitService rateLimitService) {
        this.wafService = wafService;
        this.rateLimitService = rateLimitService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();
        
        if (path.startsWith("/actuator") || path.startsWith("/metrics")) {
            chain.doFilter(request, response);
            return;
        }

        String clientIp = IpUtil.getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        // === OPTIMIZATION 1+5: Early rate-limit check before full WAF pipeline ===
        if (!rateLimitService.isAllowed(clientIp, path)) {
            httpResponse.setStatus(403);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\": \"Rate limit exceeded\"}");
            log.debug("Rate limited: {}", clientIp);
            return;
        }
        // Mark that rate limit was already checked to avoid double-counting
        httpRequest.setAttribute("waf.ratelimit.checked", Boolean.TRUE);

        wafService.processRequest(clientIp, path, userAgent, httpRequest, httpResponse);

        if (httpResponse.getStatus() == 403) {
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\": \"Forbidden\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}