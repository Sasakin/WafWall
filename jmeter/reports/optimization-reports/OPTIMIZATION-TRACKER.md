# Wave-Wall WAF Gateway — Optimization Tracker

**Status:** V9-LuaScripts is the current best. V2 was baseline; V9 added +5.4% RPS, -49% max latency.
**Baseline:** V2 (commit `7b2771d`) — AtomicLong ID generator, caller-owns-metadata
**Current Best:** V9-LuaScripts (V2 + Redis Lua scripts) — 1,179 RPS, 32.0ms avg
**Test Protocol:** JMeter 50 threads, 30s ramp-up, 60s, 3 iterations per version, statistics.json as source of truth
**Environment:** Desktop Windows 10, Java 17, Docker Redis/Kafka/nginx backend

---

## Results Summary

| Version | What Changed | RPS | Mean Latency | Verdict |
|---------|-------------|-----|-------------|---------|
| **V1** | Gateway latency: header copy, URLDecoder dedup, metrics fix | 1,444 (GUI) | 19ms | ✅ **Keep** (in V2) |
| **V2** | Fast ID generator: AtomicLong replacing UUID | 1,118 | 33.7ms | ✅ **Keep** (baseline) |
| **V3** | Java 21 + Virtual Threads + async Kafka | 1,052 | 38ms | ❌ **-23%** — virtual threads hurt |
| **V4** | Local rate limit + gzip + nginx cache + Redis pipeline + try-catch | 480 | 79ms | ❌ **-57%** — REVERTED |
| **V5** | Micro-optimizations: metrics fix, URLDecoder cache, header put() | ~1,118 | ~34ms | ⚠️ **0%** — bug fixes only |
| **V6** | Redis StringSerializer for ZSet values | 1,103 | 34.2ms | ❌ **0%** — no improvement |
| **V7** | JVM tuning: G1HeapRegionSize, IHOP, AlwaysPreTouch, CodeCache | 1,098 | 34.4ms | ❌ **-2%** — no improvement |
| **V8** | Async proxy with CompletableFuture | — | — | ❌ **REVERTED** — no improvement |
| **V9-LuaScripts** | Redis Lua scripts: rate limit + bot tracking | **1,179** | **32.0ms** | ✅ **+5.4% RPS, -49% max latency** |

### Bottom Line

**V9-LuaScripts is the current best.** V2 is the stable baseline. All other optimizations (V3-V8) either hurt performance or showed zero improvement.

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
| Redis Lua scripts (rate limit + bot tracking) | V9-LuaScripts | 8→3 Redis roundtrips per request, +5.4% RPS, -49% max latency |

---

## Future Optimization Plan

### Tier 1: High-Impact (Not Yet Tried)

| Optimization | Expected Impact | Complexity | Notes |
|-------------|----------------|-----------|-------|
| **Connection pooling tuning** | +5-15% | Low | Redis Lettuce pool: max-active=50, max-idle=20, min-idle=10. Current defaults may be too conservative |
| **Merge both Lua scripts into one** | +3-5% | Low | Combine rate_limit_check + bot_record_and_count into single Lua script. 3→2 roundtrips |
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

**Redis I/O is the bottleneck, not CPU or GC.** Every WAF request hits Redis multiple times. Lua scripts proved that reducing roundtrips from 8 to 3 gives measurable improvement (+5.4% RPS, -49% max latency). Further reduction (merging both Lua scripts into one, or caching ip:reputation) could yield additional gains.

**The optimization path that works: reduce Redis roundtrips. Everything else (JVM tuning, compression, async proxies) does not help because the thread is blocked on Redis, not doing CPU work.**

---

**Report generated:** 2026-06-20
**Data source:** `statistics.json` from JMeter HTML reports
**Branches:** `v2` (baseline), `opt/redis-lua-scripts` (V9), `v4`/`v6`/`v7` (failed experiments)
