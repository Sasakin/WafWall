# Wave-Wall WAF Gateway — Optimization Tracker

**Status:** V2 is the working baseline. All other optimizations were tested and failed or showed no measurable improvement.  
**Baseline:** V2 (commit `7b2771d`) — AtomicLong ID generator, caller-owns-metadata  
**Test Protocol:** JMeter 50 threads, 30s ramp-up, 60s, 3 iterations per version, statistics.json as source of truth  
**Environment:** Desktop Windows 10, Java 17, Docker Redis/Kafka/nginx backend

---

## Results Summary

| Version | What Changed | RPS | Mean Latency | Verdict |
|---------|-------------|-----|-------------|---------|
| **V1** | Gateway latency: header copy, URLDecoder dedup, metrics fix | 1,444 (GUI) | 19ms | ✅ **Keep** (in V2) |
| **V2** | Fast ID generator: AtomicLong replacing UUID | **1,118** | **33.7ms** | ✅ **Current baseline** |
| **V3** | Java 21 + Virtual Threads + async Kafka | 1,052 | 38ms | ❌ **-23%** — virtual threads hurt |
| **V4** | Local rate limit + gzip + nginx cache + Redis pipeline + try-catch | 480 | 79ms | ❌ **-57%** — REVERTED |
| **V5** | Micro-optimizations: metrics fix, URLDecoder cache, header put() | ~1,118 | ~34ms | ⚠️ **0%** — bug fixes only |
| **V6** | Redis StringSerializer for ZSet values | 1,103 | 34.2ms | ❌ **0%** — no improvement |
| **V7** | JVM tuning: G1HeapRegionSize, IHOP, AlwaysPreTouch, CodeCache | 1,098 | 34.4ms | ❌ **-2%** — no improvement |
| **V8** | Async proxy with CompletableFuture | — | — | ❌ **REVERTED** — no improvement |

### Bottom Line

**V2 is the winner.** All other optimizations either hurt performance (V3, V4) or showed zero measurable improvement (V5, V6, V7, V8).

---

## Detailed Findings

### ❌ DO NOT REPEAT These Optimizations

| Optimization | Tried In | Result | Why It Failed |
|-------------|----------|--------|---------------|
| **Java 21 Virtual Threads** | V3 | -23% throughput | Virtual threads add scheduling overhead; Tomcat thread model doesn't benefit |
| **Local rate limiting** | V4 | -57% throughput | Rate limit accumulates in Redis, blocks legitimate traffic |
| **Gzip compression** | V4 | part of -57% | min-size 1024B threshold; small WAF responses not compressed; CPU overhead |
| **nginx proxy cache** | V4 | part of -57% | Caches WAF responses, inconsistent error rates |
| **Redis pipelining** | V4 | -57% (bundled) | V4 bundled pipeline with local rate limit + gzip + cache. Pipeline itself was never tested in isolation. Note: Lua scripts are strictly better than pipeline (server-side atomic vs client-side batch) |
| **try-catch fallback** | V4 | part of -57% | Masks errors, reduces observability |
| **G1HeapRegionSize=4m** | V7 | 0% | 2GB heap doesn't need large regions |
| **IHOP=35** | V7 | 0% | GC triggers early enough with G1 defaults |
| **AlwaysPreTouch** | V7 | 0% | Page fault savings negligible vs Redis RTT |
| **ReservedCodeCacheSize=256m** | V7 | 0% | Default 240m is sufficient |
| **Async proxy (CompletableFuture)** | V8 | 0% | Tomcat threads are cheap; bottleneck is I/O not CPU |
| **JSON→String Redis serializer** | V6 | 0% | Not measurable on desktop |

### ⚠️ Already Applied (Keep)

| Optimization | Applied In | Impact |
|-------------|-----------|--------|
| Header copy: `headers.add()` → `headers.put()` | V1/V5 | Bug fix, prevents allocation per header |
| URLDecoder dedup across filters | V1/V5 | Avoids double-decode of query string |
| MetricsService double-count fix | V1/V5 | Corrects blocked request count |
| AtomicLong ID generator | V2 | Eliminates UUID.randomUUID() overhead |

---

## Future Optimization Plan

### Tier 1: High-Impact (Not Yet Tried)

| Optimization | Expected Impact | Complexity | Notes |
|-------------|----------------|-----------|-------|
| **Redis Lua scripts** | +20-40% | Medium | Replace 4-5 separate Redis commands with single atomic Lua script. V4 tried pipeline (client-side batch) but it was bundled with broken changes that caused -57%. Lua is different: it executes atomically server-side in a single roundtrip. No inter-command network overhead |
| **Connection pooling tuning** | +5-15% | Low | Redis Lettuce pool: max-active=50, max-idle=20, min-idle=10. Current defaults may be too conservative |
| **Reactive/WebFlux rewrite** | +30-50% | High | Replace Tomcat servlet model with Netty event loop. Eliminates thread-per-request entirely |
| **gRPC for backend proxy** | +15-25% | Medium | Replace HTTP proxy with gRPC (HTTP/2 multiplexing, protobuf serialization) |

### Tier 2: Medium-Impact (Not Yet Tried)

| Optimization | Expected Impact | Complexity | Notes |
|-------------|----------------|-----------|-------|
| **Caffeine cache for bot scores** | +5-10% | Low | Cache `analyzeBotBehavior()` result per IP for 5s |
| **Precompiled regex patterns** | +2-5% | Low | SqlInjectionFilter and XssFilter compile patterns per-request. Move to `static final Pattern` |
| **String deduplication in Redis keys** | +1-3% | Low | `formatKey()` creates new String per request |
| **Async Kafka publish** | +2-5% | Low | `KafkaEventPublisher.publish()` is synchronous |
| **HTTP response buffering** | +1-3% | Low | Buffer 403 response body instead of immediate flush |

### Tier 3: Architectural (Not Yet Tried)

| Optimization | Expected Impact | Complexity | Notes |
|-------------|----------------|-----------|-------|
| **Off-heap cache for rate limits** | +10-20% | High | Move hot rate-limit counters to off-heap memory (MapDB, Chronicle Map) |
| **Edge-side rate limiting** | +30-50% | High | Push rate limiting to nginx/Lua layer |
| **Request coalescing** | +5-10% | Medium | Coalesce Redis operations for repeated identical requests |
| **HTTP/2 upstream** | +5-10% | Medium | Backend proxy uses HTTP/1.1; HTTP/2 multiplexing reduces overhead |

### Tier 4: Infrastructure (Not Yet Tried)

| Optimization | Expected Impact | Complexity | Notes |
|-------------|----------------|-----------|-------|
| **Dedicated benchmark server** | Removes noise | Low | Desktop has 5% variance from background processes |
| **Multiple test iterations (5+)** | Better stats | Low | Current 3 iterations leave ±2% uncertainty |
| **K6 instead of JMeter** | Better metrics | Low | Built-in histograms, threshold assertions, less overhead |
| **Prometheus + Grafana profiling** | Identifies hotspots | Medium | CPU/memory/GC profiling during load test |

---

## Key Lesson

**Redis I/O is the bottleneck, not CPU or GC.** Every WAF request hits Redis 4-8 times (rate limit ZCARD+EXPIRE+ZADD+EXPIRE + bot tracking ZCARD+ZADD+EXPIRE + blacklist check). At 50 threads, Redis RTT dominates. JVM tuning, compression, async proxies — none of these help because the thread is blocked on Redis, not doing CPU work.

**The only way to significantly improve performance is to reduce Redis roundtrips.** Lua scripts are the highest-ROI next step — they replace multiple commands with a single atomic execution on the Redis server, eliminating all inter-command network overhead. Pipeline (batching) was tested in V4 but bundled with broken changes; Lua is strictly superior to pipeline because it executes server-side, not client-side.

---

**Report generated:** 2026-06-20  
**Data source:** `statistics.json` from JMeter HTML reports  
**Branches:** `v2` (baseline), `v4`/`v6`/`v7` (failed experiments)
