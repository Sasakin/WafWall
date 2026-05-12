package com.waf.gateway.service;

import com.waf.common.model.SecurityEvent;

public interface EventPublisher {

    void publish(SecurityEvent event);
}