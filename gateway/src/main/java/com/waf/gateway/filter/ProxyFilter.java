package com.waf.gateway.filter;

import com.waf.gateway.service.ProxyService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(2)
public class ProxyFilter implements Filter {

    private final ProxyService proxyService;

    public ProxyFilter(ProxyService proxyService) {
        this.proxyService = proxyService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String path = httpRequest.getRequestURI();

        if (isLocalEndpoint(path)) {
            chain.doFilter(request, response);
            return;
        }

        proxyService.proxyRequest(httpRequest, httpResponse);
    }

    private boolean isLocalEndpoint(String path) {
        return path.equals("/health") ||
               path.startsWith("/actuator") ||
               path.startsWith("/metrics") ||
               path.equals("/api/security/events") ||
               path.equals("/api/whitelist") ||
               path.startsWith("/api/circuit");
    }
}