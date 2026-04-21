package com.waf.common.repository;

import com.waf.common.model.SecurityEvent;

import java.util.List;
import java.util.Optional;

public interface SecurityEventRepository {

    void save(SecurityEvent event);

    Optional<SecurityEvent> findById(String eventId);

    List<SecurityEvent> findBySourceIp(String sourceIp);

    List<SecurityEvent> findByThreatType(com.waf.common.model.ThreatType threatType);
}