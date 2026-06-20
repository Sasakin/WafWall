package com.waf.gateway.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

// === OPTIMIZATION 2: Connection pool + remove empty body ===
@Component
public class HttpBackendClient implements BackendClient {

    @Value("${waf.backend.url:http://localhost:8080}")
    private String backendUrl;

    @Value("${waf.backend.timeout-ms:2000}")
    private int timeoutMs;

    private final RestTemplate restTemplate;

    public HttpBackendClient() {
        // === OPTIMIZATION 2: Pooled connection manager ===
        PoolingHttpClientConnectionManager connectionManager =
            new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(200);
        connectionManager.setDefaultMaxPerRoute(100);
        RequestConfig requestConfig = RequestConfig.custom()
            .setConnectionRequestTimeout(Timeout.ofMilliseconds(timeoutMs))
            .setResponseTimeout(Timeout.ofMilliseconds(timeoutMs))
            .build();

        HttpClient httpClient = HttpClients.custom()
            .setConnectionManager(connectionManager)
            .setDefaultRequestConfig(requestConfig)
            .build();

        this.restTemplate = new RestTemplate(
            new HttpComponentsClientHttpRequestFactory(httpClient));
    }

    @Override
    public void forward(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String path = request.getRequestURI();
        String queryString = request.getQueryString();

        String targetUrl = buildTargetUrl(path, queryString);

        HttpMethod method = HttpMethod.valueOf(request.getMethod());

        HttpHeaders headers = new HttpHeaders();
        copyHeaders(request, headers);

        // === OPTIMIZATION 7: null body instead of empty Map for GET requests ===
        HttpEntity<?> httpRequest;
        if ("GET".equalsIgnoreCase(request.getMethod()) ||
            "HEAD".equalsIgnoreCase(request.getMethod())) {
            httpRequest = new HttpEntity<>(headers);
        } else {
            httpRequest = new HttpEntity<>(headers);
        }

        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(
                targetUrl,
                method,
                httpRequest,
                String.class
            );

            response.setStatus(responseEntity.getStatusCode().value());

            HttpHeaders responseHeaders = responseEntity.getHeaders();
            for (Map.Entry<String, java.util.List<String>> entry : responseHeaders.entrySet()) {
                for (String value : entry.getValue()) {
                    response.addHeader(entry.getKey(), value);
                }
            }

            response.getWriter().write(responseEntity.getBody());

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
            response.getWriter().write("{\"error\": \"Backend unavailable\"}");
        }
    }

    private String buildTargetUrl(String path, String queryString) {
        String target = backendUrl + path;
        if (queryString != null && !queryString.isEmpty()) {
            target += "?" + queryString;
        }
        return target;
    }

    private void copyHeaders(HttpServletRequest request, HttpHeaders headers) {
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            String value = request.getHeader(name);

            if (!isHopByHopHeader(name)) {
                headers.add(name, value);
            }
        }

        String contentType = request.getContentType();
        if (contentType != null && !contentType.isEmpty()) {
            headers.setContentType(MediaType.parseMediaType(contentType));
        }
    }

    private boolean isHopByHopHeader(String headerName) {
        return headerName.equalsIgnoreCase("connection") ||
               headerName.equalsIgnoreCase("keep-alive") ||
               headerName.equalsIgnoreCase("proxy-authenticate") ||
               headerName.equalsIgnoreCase("proxy-authorization") ||
               headerName.equalsIgnoreCase("te") ||
               headerName.equalsIgnoreCase("trailers") ||
               headerName.equalsIgnoreCase("transfer-encoding") ||
               headerName.equalsIgnoreCase("upgrade");
    }
}
