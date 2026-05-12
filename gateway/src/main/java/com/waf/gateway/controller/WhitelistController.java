package com.waf.gateway.controller;

import com.waf.gateway.service.WhitelistService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/whitelist")
public class WhitelistController {

    private final WhitelistService whitelistService;

    public WhitelistController(WhitelistService whitelistService) {
        this.whitelistService = whitelistService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getWhitelist() {
        Map<String, Object> response = new HashMap<>();
        response.put("enabled", whitelistService.isWhitelistEnabled());
        response.put("ips", whitelistService.getWhitelistedIps());
        response.put("paths", whitelistService.getWhitelistedPaths());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/ip")
    public ResponseEntity<Map<String, Object>> addIp(@RequestBody WhitelistRequest request) {
        whitelistService.addIpToWhitelist(request.ip, request.ttlSeconds);
        
        Map<String, Object> response = new HashMap<>();
        response.put("added", true);
        response.put("ip", request.ip);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/ip/{ip}")
    public ResponseEntity<Map<String, Object>> removeIp(@PathVariable String ip) {
        whitelistService.removeFromWhitelist(ip);
        
        Map<String, Object> response = new HashMap<>();
        response.put("removed", true);
        response.put("ip", ip);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/path")
    public ResponseEntity<Map<String, Object>> addPath(@RequestBody WhitelistRequest request) {
        whitelistService.addPathToWhitelist(request.path);
        
        Map<String, Object> response = new HashMap<>();
        response.put("added", true);
        response.put("path", request.path);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/enable")
    public ResponseEntity<Map<String, Object>> enable(@RequestBody EnableRequest request) {
        whitelistService.setWhitelistEnabled(request.enabled);
        
        Map<String, Object> response = new HashMap<>();
        response.put("enabled", request.enabled);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/check/ip/{ip}")
    public ResponseEntity<Map<String, Object>> checkIp(@PathVariable String ip) {
        boolean whitelisted = whitelistService.isIpWhitelisted(ip);
        
        Map<String, Object> response = new HashMap<>();
        response.put("ip", ip);
        response.put("whitelisted", whitelisted);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/check/path")
    public ResponseEntity<Map<String, Object>> checkPath(@RequestParam String path) {
        boolean whitelisted = whitelistService.isPathWhitelisted(path);
        
        Map<String, Object> response = new HashMap<>();
        response.put("path", path);
        response.put("whitelisted", whitelisted);
        return ResponseEntity.ok(response);
    }

    public static class WhitelistRequest {
        public String ip;
        public String path;
        public Long ttlSeconds;
    }

    public static class EnableRequest {
        public boolean enabled;
    }
}