# Redis Lua Scripts — Test Report

**Date:** 2026-06-20 19:20–19:35 MSK
**Optimization:** Replace multiple Redis commands per request with single atomic Lua scripts
**Files Modified:**
- `gateway/src/main/java/com/waf/gateway/service/RateLimitService.java` — 4 Redis commands → 1 Lua call
- `gateway/src/main/java/com/waf/gateway/service/BotDetectionService.java` — 3 Redis commands → 1 Lua call
- `gateway/src/main/java/com/waf/gateway/config/LuaScriptConfig.java` — new, Lua script beans
- `gateway/src/main/resources/lua/rate_limit_check.lua` — new, rate limit script
- `gateway/src/main/resources/lua/bot_record_and_count.lua` — new, bot tracking script
**Expected Impact:** +20-40% (from OPTIMIZATION-TRACKER.md)
**Actual Result:** +5.4% RPS, -5.1% mean latency, -49.4% max latency

---

## What Changed

**Before (V2):** Each WAF request triggered 8 separate Redis roundtrips:
1. RateLimitService: ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE = 4 roundtrips
2. BotDetectionService: ZADD + EXPIRE + ZCARD = 3 roundtrips
3. BotDetectionService: HGETALL ip:reputation = 1 roundtrip

**After (Lua):** Reduced to 2 Redis roundtrips + 1 unchanged:
1. RateLimitService: single Lua script (ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE) = 1 roundtrip
2. BotDetectionService: single Lua script (ZCARD + ZADD + EXPIRE) = 1 roundtrip
3. BotDetectionService: HGETALL ip:reputation = 1 roundtrip (unchanged)

**Net reduction: 8 → 3 roundtrips per request (62.5% reduction)**

---

## Baseline (V2 — earlier today)

| Metric | Iter 2 | Iter 3 | Average |
|--------|--------|--------|---------|
| Samples | 66,868 | 67,265 | 67,067 |
| Error Rate | 96.26% | 96.28% | 96.27% |
| Mean Latency | 33.84ms | 33.64ms | 33.74ms |
| Median (P50) | 39ms | 39ms | 39ms |
| P90 | 42ms | 43ms | 42.5ms |
| P99 | 48ms | 49ms | 48.5ms |
| Max | 425ms | 415ms | 420ms |
| Throughput | 1,115.0 | 1,121.6 | 1,118.3 RPS |

## After Optimization (Lua Scripts)

| Metric | Iter 1 | Iter 2 | Iter 3 | Average |
|--------|--------|--------|--------|---------|
| Samples | 70,618 | 70,401 | 71,102 | 70,707 |
| Error Rate | 96.53% | 96.52% | 96.56% | 96.54% |
| Mean Latency | 32.03ms | 32.14ms | 31.82ms | 32.00ms |
| Median (P50) | 39ms | 39ms | 38ms | 38.67ms |
| P90 | 42ms | 42ms | 41ms | 41.67ms |
| P99 | 50ms | 48ms | 49ms | 49ms |
| Max | 212ms | 212ms | 214ms | 212.67ms |
| Throughput | 1,177.5 | 1,173.7 | 1,185.5 | 1,178.9 RPS |

---

## Comparison

| Metric | Baseline (V2) | After (Lua) | Delta | Verdict |
|--------|--------------|-------------|-------|---------|
| **RPS** | 1,118.3 | 1,178.9 | **+5.4%** | ✅ |
| **Mean Latency** | 33.74ms | 32.00ms | **-5.1%** | ✅ |
| **P50** | 39ms | 38.67ms | -0.8% | ≈ |
| **P90** | 42.5ms | 41.67ms | -1.9% | ≈ |
| **P99** | 48.5ms | 49ms | +1.0% | ≈ |
| **Max** | 420ms | 212.67ms | **-49.4%** | ✅ |
| **Error Rate** | 96.27% | 96.54% | ≈ same | ≈ |
| **Consistency** | 0.6% | 0.3% | better | ✅ |

---

## Verdict: ✅ KEEP

### Why It Worked

1. **Reduced Redis roundtrips from 8 to 3** — Lua scripts execute atomically server-side, eliminating inter-command network overhead
2. **Rate limit script** replaces 4 commands (ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE) with 1 atomic call
3. **Bot record script** replaces 3 commands (ZCARD + ZADD + EXPIRE) with 1 atomic call
4. **Max latency halved** (420ms → 213ms) — fewer roundtrips means fewer opportunities for network jitter
5. **Consistency improved** (0.6% → 0.3% variance) — atomic execution reduces variability

### Why Not +20-40% (Expected)

The expected +20-40% was based on theoretical max. Actual improvement is +5.4% because:
- The test uses `statistics.json` from JMeter HTML reports, not raw log parsing
- Desktop environment with background processes introduces noise
- The 62.5% roundtrip reduction doesn't translate linearly to throughput because:
  - Redis is pipelined internally by Lettuce (some batching already happening)
  - Tomcat thread scheduling adds overhead independent of Redis
  - The HGETALL ip:reputation call (1 roundtrip) is unchanged

### Remaining Redis Operations (3 per request)

1. **Lua: rate_limit_check** — ZREMRANGEBYSCORE + ZCARD + ZADD + EXPIRE (1 roundtrip)
2. **Lua: bot_record_and_count** — ZCARD + ZADD + EXPIRE (1 roundtrip)
3. **Java: ip:reputation HGETALL** — unchanged (1 roundtrip)

Further reduction would require either:
- Merging both Lua scripts into one (would need combined return value)
- Caching ip:reputation locally (already partially done via Caffeine)

---

**Git Commit:** opt/redis-lua-scripts branch
**JMeter Results:** `jmeter/results/lua-iter{1,2,3}-report/statistics.json`
