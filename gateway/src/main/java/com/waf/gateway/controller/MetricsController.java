package com.waf.gateway.controller;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.ThreadMXBean;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/metrics")
public class MetricsController {

    @GetMapping("/system")
    public ResponseEntity<Map<String, Object>> getSystemMetrics() {
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        
        Map<String, Object> metrics = new HashMap<>();
        
        // Memory
        metrics.put("heapUsed", memoryBean.getHeapMemoryUsage().getUsed());
        metrics.put("heapMax", memoryBean.getHeapMemoryUsage().getMax());
        metrics.put("heapCommitted", memoryBean.getHeapMemoryUsage().getCommitted());
        
        // Threads
        metrics.put("threadCount", threadBean.getThreadCount());
        metrics.put("peakThreadCount", threadBean.getPeakThreadCount());
        metrics.put("daemonThreadCount", threadBean.getDaemonThreadCount());
        
        // Runtime
        metrics.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime());
        
        return ResponseEntity.ok(metrics);
    }

    @GetMapping("/jvm")
    public ResponseEntity<Map<String, Object>> getJvmMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // GC
        var gcBeans = ManagementFactory.getGarbageCollectorMXBeans();
        Map<String, Long> gcStats = new HashMap<>();
        for (var gc : gcBeans) {
            gcStats.put(gc.getName() + "_count", gc.getCollectionCount());
            gcStats.put(gc.getName() + "_time", gc.getCollectionTime());
        }
        metrics.put("gc", gcStats);
        
        // Memory pools
        var memoryPools = ManagementFactory.getMemoryPoolMXBeans();
        Map<String, Map<String, Long>> poolStats = new HashMap<>();
        for (var pool : memoryPools) {
            Map<String, Long> poolData = new HashMap<>();
            poolData.put("used", pool.getUsage().getUsed());
            poolData.put("max", pool.getUsage().getMax());
            poolStats.put(pool.getName(), poolData);
        }
        metrics.put("memoryPools", poolStats);
        
        return ResponseEntity.ok(metrics);
    }
}