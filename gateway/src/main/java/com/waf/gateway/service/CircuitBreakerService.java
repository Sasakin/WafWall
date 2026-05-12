package com.waf.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@Slf4j
public class CircuitBreakerService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${waf.circuit-breaker.enabled:true}")
    private boolean circuitBreakerEnabled;

    @Value("${waf.circuit-breaker.failure-threshold:5}")
    private int failureThreshold;

    @Value("${waf.circuit-breaker.success-threshold:3}")
    private int successThreshold;

    @Value("${waf.circuit-breaker.timeout-seconds:30}")
    private int timeoutSeconds;

    @Value("${waf.circuit-breaker.half-open-max-calls:3}")
    private int halfOpenMaxCalls;

    public enum CircuitState {
        CLOSED,      // Normal operation
        OPEN,       // Failing, reject requests
        HALF_OPEN   // Testing if service recovered
    }

    private final Map<String, CircuitBreaker> breakers = new ConcurrentHashMap<>();

    public CircuitBreakerService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean isAvailable(String service) {
        if (!circuitBreakerEnabled) {
            return true;
        }

        CircuitBreaker cb = getCircuitBreaker(service);
        return cb.isAvailable();
    }

    public void recordSuccess(String service) {
        getCircuitBreaker(service).recordSuccess();
    }

    public void recordFailure(String service) {
        getCircuitBreaker(service).recordFailure();
    }

    public CircuitState getState(String service) {
        return getCircuitBreaker(service).getState();
    }

    public void reset(String service) {
        breakers.remove(service);
        try {
            redisTemplate.delete("circuit:" + service + ":state");
            redisTemplate.delete("circuit:" + service + ":failures");
            log.info("Circuit breaker reset for service: {}", service);
        } catch (Exception e) {
            log.error("Error resetting circuit breaker: {}", e.getMessage());
        }
    }

    public Map<String, Object> getStatus(String service) {
        CircuitBreaker cb = getCircuitBreaker(service);
        
        Map<String, Object> status = new HashMap<>();
        status.put("service", service);
        status.put("state", cb.getState());
        status.put("failureCount", cb.getFailureCount());
        status.put("successCount", cb.getSuccessCount());
        status.put("lastFailureTime", cb.getLastFailureTime());
        status.put("lastSuccessTime", cb.getLastSuccessTime());
        
        return status;
    }

    public Map<String, Object> getAllStatus() {
        Map<String, Object> status = new HashMap<>();
        
        for (String service : breakers.keySet()) {
            status.put(service, getStatus(service));
        }
        
        return status;
    }

    private CircuitBreaker getCircuitBreaker(String service) {
        return breakers.computeIfAbsent(service, k -> new CircuitBreaker(service));
    }

    class CircuitBreaker {
        private final String service;
        private final AtomicInteger failureCount = new AtomicInteger(0);
        private final AtomicInteger successCount = new AtomicInteger(0);
        private volatile Instant lastFailureTime;
        private volatile Instant lastSuccessTime;
        private volatile CircuitState state = CircuitState.CLOSED;
        private volatile Instant stateChangeTime;
        private volatile int halfOpenCalls = 0;

        CircuitBreaker(String service) {
            this.service = service;
            loadStateFromRedis();
        }

        boolean isAvailable() {
            switch (state) {
                case CLOSED:
                    return true;
                case OPEN:
                    // Check if timeout has passed to transition to HALF_OPEN
                    if (stateChangeTime != null) {
                        long elapsed = Instant.now().getEpochSecond() - stateChangeTime.getEpochSecond();
                        if (elapsed > timeoutSeconds) {
                            transitionToHalfOpen();
                            return true;
                        }
                    }
                    return false;
                case HALF_OPEN:
                    // Allow limited calls in half-open state
                    if (halfOpenCalls < halfOpenMaxCalls) {
                        halfOpenCalls++;
                        return true;
                    }
                    return false;
                default:
                    return true;
            }
        }

        void recordSuccess() {
            lastSuccessTime = Instant.now();
            successCount.incrementAndGet();
            failureCount.set(0);

            if (state == CircuitState.HALF_OPEN) {
                if (successCount.get() >= successThreshold) {
                    transitionToClosed();
                }
            } else if (state == CircuitState.CLOSED) {
                // Reset success counter periodically
                if (successCount.get() > 100) {
                    successCount.set(0);
                }
            }
            
            saveStateToRedis();
        }

        void recordFailure() {
            lastFailureTime = Instant.now();
            int failures = failureCount.incrementAndGet();

            if (state == CircuitState.HALF_OPEN) {
                transitionToOpen();
            } else if (state == CircuitState.CLOSED) {
                if (failures >= failureThreshold) {
                    transitionToOpen();
                }
            }
            
            saveStateToRedis();
        }

        CircuitState getState() {
            return state;
        }

        int getFailureCount() {
            return failureCount.get();
        }

        int getSuccessCount() {
            return successCount.get();
        }

        Instant getLastFailureTime() {
            return lastFailureTime;
        }

        Instant getLastSuccessTime() {
            return lastSuccessTime;
        }

        private void transitionToOpen() {
            log.warn("Circuit breaker OPEN for service: {} (failures: {})", service, failureCount.get());
            state = CircuitState.OPEN;
            stateChangeTime = Instant.now();
            saveStateToRedis();
        }

        private void transitionToHalfOpen() {
            log.info("Circuit breaker HALF_OPEN for service: {}", service);
            state = CircuitState.HALF_OPEN;
            stateChangeTime = Instant.now();
            halfOpenCalls = 0;
            saveStateToRedis();
        }

        private void transitionToClosed() {
            log.info("Circuit breaker CLOSED for service: {}", service);
            state = CircuitState.CLOSED;
            stateChangeTime = Instant.now();
            failureCount.set(0);
            successCount.set(0);
            saveStateToRedis();
        }

        private void loadStateFromRedis() {
            try {
                String stateKey = "circuit:" + service + ":state";
                String failKey = "circuit:" + service + ":failures";
                
                Object stateObj = redisTemplate.opsForValue().get(stateKey);
                if (stateObj != null) {
                    state = CircuitState.valueOf(stateObj.toString());
                }
                
                Object failObj = redisTemplate.opsForValue().get(failKey);
                if (failObj != null) {
                    failureCount.set(Integer.parseInt(failObj.toString()));
                }
                
                if (state == CircuitState.OPEN) {
                    stateChangeTime = Instant.now();
                }
            } catch (Exception e) {
                log.debug("Error loading circuit breaker state: {}", e.getMessage());
            }
        }

        private void saveStateToRedis() {
            try {
                String stateKey = "circuit:" + service + ":state";
                String failKey = "circuit:" + service + ":failures";
                
                redisTemplate.opsForValue().set(stateKey, state.name(), 30, TimeUnit.MINUTES);
                redisTemplate.opsForValue().set(failKey, failureCount.get(), 30, TimeUnit.MINUTES);
            } catch (Exception e) {
                log.debug("Error saving circuit breaker state: {}", e.getMessage());
            }
        }
    }

    public void setCircuitBreakerEnabled(boolean enabled) {
        this.circuitBreakerEnabled = enabled;
    }
}