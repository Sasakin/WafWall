package com.waf.gateway.filter;

import com.waf.gateway.service.ProxyService;
import com.waf.gateway.service.WafService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(2)
public class ProxyFilter implements Filter {

    private final WafService wafService;
    private final ProxyService proxyService;

    public ProxyFilter(WafService wafService, ProxyService proxyService) {
        this.wafService = wafService;
        this.proxyService = proxyService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String clientIp = getClientIp(httpRequest);
        String path = httpRequest.getRequestURI();
        String userAgent = httpRequest.getHeader("User-Agent");

        // Process through WAF filters first
        wafService.processRequest(clientIp, path, userAgent, httpRequest, httpResponse);

        // If blocked by WAF, don't proxy
        if (httpResponse.getStatus() == 403) {
            return;
        }

        // Skip proxy for local endpoints - continue to controller
        if (isLocalEndpoint(path)) {
            chain.doFilter(request, response);
            return;
        }

        // If request passed WAF, proxy to backend
        proxyService.proxyRequest(httpRequest, httpResponse);
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private boolean isLocalEndpoint(String path) {
        return path.equals("/health") ||
               path.startsWith("/actuator") ||
               path.startsWith("/metrics") ||
               path.equals("/api/security/events") ||
               path.equals("/api/whitelist") ||
               path.startsWith("/api/circuit") ||
               path.startsWith("/api/");
    }
}