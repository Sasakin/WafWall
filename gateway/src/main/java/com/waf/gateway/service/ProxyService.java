package com.waf.gateway.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class ProxyService {

    private final BackendClient backendClient;

    public ProxyService(BackendClient backendClient) {
        this.backendClient = backendClient;
    }

    public void proxyRequest(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        backendClient.forward(request, response);
    }
}