package com.waf.gateway.controller;

import com.waf.gateway.service.CircuitBreakerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/circuit")
public class CircuitBreakerController {

    private final CircuitBreakerService circuitBreakerService;

    public CircuitBreakerController(CircuitBreakerService circuitBreakerService) {
        this.circuitBreakerService = circuitBreakerService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getStatus() {
        return ResponseEntity.ok(circuitBreakerService.getAllStatus());
    }

    @GetMapping("/{service}")
    public ResponseEntity<Map<String, Object>> getServiceStatus(@PathVariable String service) {
        return ResponseEntity.ok(circuitBreakerService.getStatus(service));
    }

    @GetMapping("/{service}/available")
    public ResponseEntity<Map<String, Object>> isAvailable(@PathVariable String service) {
        boolean available = circuitBreakerService.isAvailable(service);
        
        return ResponseEntity.ok(Map.of(
            "service", service,
            "available", available,
            "state", circuitBreakerService.getState(service)
        ));
    }

    @PostMapping("/{service}/reset")
    public ResponseEntity<Map<String, Object>> reset(@PathVariable String service) {
        circuitBreakerService.reset(service);
        
        return ResponseEntity.ok(Map.of(
            "service", service,
            "reset", true
        ));
    }

    @PostMapping("/{service}/record-success")
    public ResponseEntity<Map<String, Object>> recordSuccess(@PathVariable String service) {
        circuitBreakerService.recordSuccess(service);
        
        return ResponseEntity.ok(Map.of(
            "service", service,
            "action", "success_recorded"
        ));
    }

    @PostMapping("/{service}/record-failure")
    public ResponseEntity<Map<String, Object>> recordFailure(@PathVariable String service) {
        circuitBreakerService.recordFailure(service);
        
        return ResponseEntity.ok(Map.of(
            "service", service,
            "action", "failure_recorded"
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        boolean redisAvailable = circuitBreakerService.isAvailable("redis");
        boolean kafkaAvailable = circuitBreakerService.isAvailable("kafka");
        
        String status = (redisAvailable && kafkaAvailable) ? "UP" : "DEGRADED";
        
        return ResponseEntity.ok(Map.of(
            "status", status,
            "redis", circuitBreakerService.getState("redis"),
            "kafka", circuitBreakerService.getState("kafka")
        ));
    }
}