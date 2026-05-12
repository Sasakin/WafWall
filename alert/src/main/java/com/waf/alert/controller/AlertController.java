package com.waf.alert.controller;

import com.waf.alert.service.AlertService;
import com.waf.alert.service.BlocklistService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService alertService;
    private final BlocklistService blocklistService;

    public AlertController(AlertService alertService, BlocklistService blocklistService) {
        this.alertService = alertService;
        this.blocklistService = blocklistService;
    }

    @GetMapping("")
    public ResponseEntity<Map<String, Object>> getAlerts() {
        Map<String, Object> response = new HashMap<>();
        response.put("totalAlerts", alertService.getTotalAlerts());
        response.put("recentStats", alertService.getAlertStats());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("blocklistSize", blocklistService.getBlocklistSize());
        stats.put("alertStats", alertService.getAlertStats());
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/blocklist")
    public ResponseEntity<Map<String, Object>> getBlocklist() {
        Map<String, Object> response = new HashMap<>();
        response.put("blockedIps", blocklistService.getBlockedIps());
        response.put("size", blocklistService.getBlocklistSize());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/block")
    public ResponseEntity<Map<String, Object>> blockIp(@RequestBody BlockRequest request) {
        if (request.ip == null || request.ip.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "IP is required"));
        }

        blocklistService.addToBlocklist(request.ip, request.reason);
        Map<String, Object> response = new HashMap<>();
        response.put("blocked", true);
        response.put("ip", request.ip);
        response.put("reason", request.reason);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/block/{ip}")
    public ResponseEntity<Map<String, Object>> unblockIp(@PathVariable String ip) {
        blocklistService.removeFromBlocklist(ip);
        Map<String, Object> response = new HashMap<>();
        response.put("blocked", false);
        response.put("ip", ip);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/blocklist/clear")
    public ResponseEntity<Map<String, Object>> clearBlocklist() {
        blocklistService.clearBlocklist();
        Map<String, Object> response = new HashMap<>();
        response.put("cleared", true);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/cleanup")
    public ResponseEntity<Map<String, Object>> cleanup() {
        alertService.cleanup();
        Map<String, Object> response = new HashMap<>();
        response.put("cleaned", true);
        return ResponseEntity.ok(response);
    }

    public static class BlockRequest {
        public String ip;
        public String reason;
        public Long ttlSeconds;
    }
}