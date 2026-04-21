package com.waf.gateway.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HealthController {

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private KafkaTemplate<String, Object> kafkaTemplate;

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        
        Map<String, String> components = new HashMap<>();
        
        // Redis check
        try {
            if (redisTemplate != null) {
                redisTemplate.getConnectionFactory().getConnection().ping();
                components.put("redis", "UP");
            } else {
                components.put("redis", "NOT_CONFIGURED");
            }
        } catch (Exception e) {
            components.put("redis", "DOWN");
        }
        
        // Kafka check
        try {
            if (kafkaTemplate != null) {
                components.put("kafka", "UP");
            } else {
                components.put("kafka", "NOT_CONFIGURED");
            }
        } catch (Exception e) {
            components.put("kafka", "DOWN");
        }
        
        boolean allUp = components.values().stream().allMatch("UP"::equals);
        
        response.put("status", allUp ? "UP" : "DEGRADED");
        response.put("timestamp", Instant.now());
        response.put("components", components);
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health/liveness")
    public ResponseEntity<Map<String, Object>> liveness() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("timestamp", Instant.now());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health/readiness")
    public ResponseEntity<Map<String, Object>> readiness() {
        Map<String, Object> response = new HashMap<>();
        
        boolean ready = true;
        
        try {
            if (redisTemplate != null) {
                redisTemplate.getConnectionFactory().getConnection().ping();
            }
        } catch (Exception e) {
            ready = false;
        }
        
        if (ready) {
            response.put("status", "READY");
        } else {
            response.put("status", "NOT_READY");
        }
        
        response.put("timestamp", Instant.now());
        return ResponseEntity.ok(response);
    }
}