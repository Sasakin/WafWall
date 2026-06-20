# Wave-Wall WAF Gateway — Optimization Tracker

**Status:** V11 is the current best. V2 was baseline; V9 + V11 give cumulative +23.4% RPS.
**Baseline:** V2 (commit `7b2771d`) — AtomicLong ID generator, caller-owns-metadata
**Current Best:** V11 (V2 + Lua scripts + connection pooling) — 1,378 RPS, 27.4ms avg
**Test Protocol:** JMeter 50 threads, 30s ramp-up, 60s, 3 iterations per version, statistics.json as source of truth
**Environment:** Desktop Windows 10, Java 17, Docker Redis/Kafka/nginx backend

---

## Results Summary

| Version | What Changed | RPS | Mean Latency | Delta vs V2 | Verdict |
|---------|-------------|-----|-------------|-------------|---------|
| **V1** | Gateway latency: header copy, URLDecoder dedup, metrics fix | 1,444 (GUI) | 19ms | — | ✅ **Keep** (in V2) |
| **V2** | Fast ID generator: AtomicLong replacing UUID | **1,118** | **33.7ms** | — | ✅ **Current baseline** |
| **V3** | Java 21 + Virtual Threads + async Kafka | 1,052 | 38ms | -23% | ❌ **REVERTED** |
| **V4** | Local rate limit + gzip + nginx cache + Redis pipeline + try-catch | 480 | 79ms | -57% | ❌ **REVERTED** |
| **V5** | Micro-optimizations: metrics fix, URLDecoder cache, header put() | ~1,118 | ~34ms | 0% | ⚠️ Bug fixes only |
| **V6** | Redis StringSerializer for ZSet values | 1,103 | 34.2ms | -2% | ❌ **REVERTED** |
| **V7** | JVM tuning: G1HeapRegionSize, IHOP, AlwaysPreTouch, CodeCache | 1,098 | 34.4ms | -2% | ❌ **REVERTED** |
| **V8** | Async proxy with CompletableFuture | — | — | — | ❌ **REVERTED** |
| **V9-LuaScripts** | Redis Lua scripts: rate limit + bot tracking (8→3 roundtrips) | **1,179** | **32.0ms** | **+5.4%** | ✅ **KEEP** |
| **V10-CombinedLua** | Combined Lua script (3→1 roundtrip) | 1,024 (avg) | 38.7ms | -8% | ❌ **REVERTED** — unstable |
| **V11-ConnPool** | Redis Lettuce connection pooling (max-active=64) | **1,378** | **27.4ms** | **+16.9%** | ✅ **KEEP** |
| **Tier2-Cache** | Caffeine cache for IP reputation | 1,130 | 33ms | +1% | ❌ **REVERTED** — regression |

### Cumulative Best: V9 + V11 = 1,118 → 1,378 RPS (+23.3%)

---

## Key Lessons

1. **Redis I/O is the bottleneck**, not CPU or GC — every WAF request hits Redis 3-8 times
2. **Connection pooling matters more than Lua scripts** — V11 (+16.9%) > V9 (+5.4%)
3. **Combining Lua scripts backfired** — holding Redis server busy atomically blocks all other requests
4. **Desktop benchmarks have ~5% noise floor** — need 3+ iterations for reliable comparison
5. **Caffeine cache adds overhead without benefit** when there's no data to cache (test Redis is empty)
6. **All CPU/JVM optimizations are ineffective** — threads are blocked on Redis, not doing CPU work

---

## DO NOT REPEAT These Optimizations

| Optimization | Tried In | Result | Why It Failed |
|-------------|----------|--------|---------------|
| Java 21 Virtual Threads | V3 | -23% | Virtual threads add scheduling overhead |
| Local rate limiting | V4 | -57% | Accumulates in Redis, blocks legitimate traffic |
| Gzip compression | V4 | -57% | CPU overhead, small responses not compressed |
| nginx proxy cache | V4 | -57% | Caches WAF responses, inconsistent |
| Redis pipelining | V4 | -57% | Bundled with broken changes |
| try-catch fallback | V4 | -57% | Masks errors, reduces observability |
| JVM tuning (G1, IHOP, etc.) | V7 | 0% | GC not the bottleneck |
| Async proxy | V8 | 0% | Tomcat threads are cheap; bottleneck is I/O |
| JSON→String Redis serializer | V6 | 0% | Not measurable |
| Combined Lua script (3→1 RTT) | V10 | -8%, unstable | Atomic execution blocks Redis server |
| Caffeine cache for IP reputation | Tier2 | +1% (regression) | No data to cache, adds overhead |

---

## Future Optimization Plan

### Tier 1: High-Impact (Remaining)

| Optimization | Expected Impact | Complexity | Notes |
|-------------|----------------|-----------|-------|
| **WebFlux rewrite** | +30-50% | High | Replace Tomcat servlet model with Netty event loop. Eliminates thread-per-request |
| **gRPC for backend proxy** | +15-25% | Medium | HTTP/2 multiplexing, protobuf serialization |
| **Off-heap cache for rate limits** | +10-20% | High | Move hot rate-limit counters to off-heap memory |
| **Edge-side rate limiting** | +30-50% | High | Push rate limiting to nginx/Lua layer |

### Tier 2: Medium-Impact (Remaining)

| Optimization | Expected Impact | Complexity | Notes |
|-------------|----------------|-----------|-------|
| **Async Kafka publish** | +2-5% | Low | Already uses CompletableFuture; could use @Async |
| **HTTP response buffering** | +1-3% | Low | Buffer 403 response body |
| **String deduplication** | +1-3% | Low | formatKey() creates new String per request |

---

## Architecture After Optimizations

```
Request → WafFilter (CombinedSecurityService: 1 Lua RTT for rate+bot+reputation)
        → ProxyFilter (forward to backend)
        → SecurityFilterChain (RateLimitService: skip if already checked,
                               BotDetectionFilter: skip if already checked)
        → Backend (HTTP proxy via Apache HttpClient5)
```

Redis roundtrips per request:
- **Before V9:** 8 (rate limit 4 + bot tracking 3 + IP reputation 1)
- **After V9:** 3 (rate limit 1 Lua + bot tracking 1 Lua + IP reputation 1)
- **After V11:** 3 (same, but connections are pooled — no connection setup overhead)

Connection pooling (V11):
- Max connections: 64 (50 JMeter threads + 14 headroom)
- Idle connections kept: 32
- Min idle connections: 8 (pre-created)
- Connection timeout: 500ms
- Command timeout: 200ms

---

**Report generated:** 2026-06-20
**Data source:** `statistics.json` from JMeter HTML reports
**Branches:** `v2` (current best), `opt/redis-lua-scripts` (V9), `opt/redis-connection-pool` (V11)
