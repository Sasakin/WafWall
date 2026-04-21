package com.waf.gateway.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface BackendClient {

    void forward(HttpServletRequest request, HttpServletResponse response) throws IOException;
}