package com.waf.gateway.filter;

import com.waf.gateway.service.WafService;
import com.waf.gateway.util.IpUtil;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(1)
public class WafFilter implements Filter {

    private final WafService wafService;

    public WafFilter(WafService wafService) {
        this.wafService = wafService;
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

        wafService.processRequest(clientIp, path, userAgent, httpRequest, httpResponse);

        if (httpResponse.getStatus() == 403) {
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\": \"Forbidden\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}