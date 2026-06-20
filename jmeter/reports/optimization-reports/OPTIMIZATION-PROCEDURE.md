# WAF Gateway Optimization — Autonomous Agent Procedure

**Purpose:** Step-by-step procedure for an AI agent to independently apply, test, and evaluate optimizations on the Wave-Wall WAF Gateway.

---

## Prerequisites

Before starting, the agent must have:

1. **Git access** to `C:\Users\sasakinme\ideaProjects\highload-architect\wave-wall`
2. **Java 17** available
3. **Docker** running (Redis, Kafka, nginx backend)
4. **JMeter 5.6.3** at `C:\Users\sasakinme\programs\apache-jmeter-5.6.3\bin\jmeter.bat`
5. **Port 8080** free
6. **Branch `v2`** checked out (the working baseline)

---

## Phase 0: Environment Verification

```powershell
# 1. Verify Java
java -version

# 2. Verify Docker services running
docker ps --format "table {{.Names}}\t{{.Status}}"
# Expected: waf-redis, waf-zookeeper, waf-kafka, waf-backend all running

# 3. Verify JMeter exists
Test-Path "C:\Users\sasakinme\programs\apache-jmeter-5.6.3\bin\jmeter.bat"

# 4. Verify no gateway running on port 8080
netstat -aon | Select-String ":8080" | Select-String "LISTENING"
# Should be empty

# 5. Verify you're on branch v2
git branch --show-current
# Should print: v2
```

---

## Phase 1: Baseline Measurement

### Step 1.1: Clean Build

```powershell
cd C:\Users\sasakinme\ideaProjects\highload-architect\wave-wall
Remove-Item -Recurse -Force gateway\build -ErrorAction SilentlyContinue
.\gradlew.bat :gateway:bootJar --no-daemon
```

Wait for `BUILD SUCCESSFUL`.

### Step 1.2: Verify Build

```powershell
Get-Item gateway\build\libs\gateway.jar | Select-Object Name, Length, LastWriteTime
jar tf gateway\build\libs\gateway.jar | Select-String "BOOT-INF/classes/" | head -10
```

### Step 1.3: Build Docker Image

```powershell
docker compose build waf-gateway-1 waf-gateway-2
```

### Step 1.4: Start Infrastructure (if not running)

```powershell
docker compose up -d redis zookeeper kafka backend
Start-Sleep -Seconds 10
docker exec waf-redis redis-cli FLUSHALL
```

### Step 1.5: Start Gateway

```powershell
$env:REDIS_HOST="localhost"
$env:REDIS_PORT="6379"
$env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
$env:WAF_BACKEND_URL="http://localhost:8080"
# Use exact JVM flags from Dockerfile.gateway (NO V7 extra flags):
java "-Xms512m" "-Xmx2g" "-XX:+UseG1GC" "-XX:MaxGCPauseMillis=50" `
  "-XX:+ParallelRefProcEnabled" "-XX:+UseStringDeduplication" `
  "-XX:+OptimizeStringConcat" `
  -jar gateway\build\libs\gateway.jar
```

Wait for `Tomcat started on port 8080`.

### Step 1.6: Health Check

```powershell
Start-Sleep -Seconds 20
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/test
# Expected: 403
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/actuator/health
# Expected: 200
```

### Step 1.6a: Baseline Functional Tests

Run functional tests to establish the baseline pass/fail state. All tests that pass on baseline must also pass on optimized version.

```powershell
cd tests
python -m pytest test_waf_gateway.py -v --tb=short
cd ..
```

Record the baseline results:
```
=== Baseline Functional Test Results ===
Passed: X / 28
Failed: Y (list each — these are expected pre-existing failures)
```

**Known pre-existing failures (not caused by code):**
- `test_health_endpoint` — Kafka timeout in HealthController

**All other tests must pass.** If they don't, the baseline itself is broken — fix before continuing.

### Step 1.7: Run JMeter — 3 Iterations

```powershell
# Iteration 1 (warmup)
Remove-Item -Recurse -Force jmeter\results\baseline-iter1-report -ErrorAction SilentlyContinue
C:\Users\sasakinme\programs\apache-jmeter-5.6.3\bin\jmeter.bat -n `
  -t jmeter\01-basic-load-test.jmx `
  -l jmeter\results\baseline-iter1.log `
  -e -o jmeter\results\baseline-iter1-report

# Iteration 2
Remove-Item -Recurse -Force jmeter\results\baseline-iter2-report -ErrorAction SilentlyContinue
C:\Users\sasakinme\programs\apache-jmeter-5.6.3\bin\jmeter.bat -n `
  -t jmeter\01-basic-load-test.jmx `
  -l jmeter\results\baseline-iter2.log `
  -e -o jmeter\results\baseline-iter2-report

# Iteration 3
Remove-Item -Recurse -Force jmeter\results\baseline-iter3-report -ErrorAction SilentlyContinue
C:\Users\sasakinme\programs\apache-jmeter-5.6.3\bin\jmeter.bat -n `
  -t jmeter\01-basic-load-test.jmx `
  -l jmeter\results\baseline-iter3.log `
  -e -o jmeter\results\baseline-iter3-report
```

### Step 1.8: Stop Gateway

```powershell
taskkill /F /IM java.exe
```

### Step 1.9: Extract Baseline Statistics

```powershell
$runs = @("baseline-iter1", "baseline-iter2", "baseline-iter3")
foreach ($run in $runs) {
    $path = "jmeter\results\$run-report\statistics.json"
    $data = Get-Content $path | ConvertFrom-Json
    echo "=== $run ==="
    echo "Samples: $($data.Total.sampleCount)"
    echo "Errors: $($data.Total.errorCount) ($([math]::Round($data.Total.errorPct, 2))%)"
    echo "Mean: $([math]::Round($data.Total.meanResTime, 2))ms"
    echo "Median: $($data.Total.medianResTime)ms"
    echo "P90: $($data.Total.pct1ResTime)ms"
    echo "P95: $($data.Total.pct2ResTime)ms"
    echo "P99: $($data.Total.pct3ResTime)ms"
    echo "RPS: $([math]::Round($data.Total.throughput, 2))"
    echo ""
}
```

### Step 1.10: Calculate Baseline Average

Use **iterations 2+3** (exclude warmup iter 1). Record:
- Average RPS
- Average Mean Latency
- Average P50, P90, P95, P99
- Variance between iter 2 and 3 (must be <5%)

---

## Phase 2: Select Optimization

### Step 2.1: Read the Tracker

```powershell
Get-Content jmeter\reports\optimization-reports\OPTIMIZATION-TRACKER.md
```

### Step 2.2: Pick the Next Optimization

From the "Future Optimization Plan" section, select the **first untried optimization** in Tier 1, then Tier 2, etc.

### Step 2.3: Verify Not Already Applied

```powershell
# Check current git log for any matching keywords
git log --oneline | Select-String "<optimization-keyword>"
```

If found, skip to next optimization.

---

## Phase 3: Implement Optimization

### Step 3.1: Document the Change

Before writing any code, record:
- What you're changing
- Which files
- Expected impact
- Risk level

### Step 3.2: Create a Feature Branch

```powershell
git checkout -b opt/<optimization-name>
```

### Step 3.3: Implement

Make the code changes. Follow existing code style. Keep changes minimal and focused.

### Step 3.4: Verify Compilation

```powershell
.\gradlew.bat :gateway:bootJar --no-daemon
```

Must succeed. If not, fix compilation errors or abort.

---

## Phase 4: Test Optimization

### Step 4.1: Clean Build + Docker

```powershell
Remove-Item -Recurse -Force gateway\build -ErrorAction SilentlyContinue
.\gradlew.bat :gateway:bootJar --no-daemon
docker compose build waf-gateway-1 waf-gateway-2
```

### Step 4.2: Reset Infrastructure

```powershell
docker exec waf-redis redis-cli FLUSHALL
```

### Step 4.3: Start Gateway

Same as Phase 1, Step 1.5.

### Step 4.4: Health Check

Same as Phase 1, Step 1.6.

### Step 4.5: Functional Tests (pytest)

Run the functional test suite **while the gateway is still running** to verify correctness before measuring performance. Tests use `conftest.py` which auto-patches User-Agent to browser UA (avoids bot detection).

```powershell
# Run only the gateway test suite
cd tests
python -m pytest test_waf_gateway.py -v --tb=short
cd ..
```

**Expected:** All tests pass except `test_health_endpoint` (known issue — Kafka timeout in health check, pre-existing).

**If new tests fail that were previously passing → REVERT the optimization immediately.** Performance gains are meaningless if functionality is broken.

Record the pass/fail counts:
```
=== Functional Test Results ===
Passed: X / 28
Failed: Y (list each failing test name)
```

**Common false failures (not caused by optimization):**
- `test_health_endpoint` — Kafka timeout in HealthController, pre-existing
- Any test with `assert response.status_code in [200, 403, 404]` — these pass even on regressions because they accept 403

**Real failures to watch for:**
- Rate limit tests (`test_rate_limit_*`) now returning different status codes
- SQL/XSS injection tests (`test_sqli_*`, `test_xss_*`) no longer blocking malicious payloads
- Bot detection tests (`test_bot_*`) now allowing known bots through
- Proxy tests (`test_proxy_*`) returning 500 instead of 200/404/502

### Step 4.6: Flush Redis + Run JMeter — 3 Iterations

```powershell
# Flush Redis before perf test
docker exec waf-redis redis-cli FLUSHALL
```

Same as Phase 1, Step 1.7, but prefix output files with the optimization name:
- `jmeter\results\<opt-name>-iter1-report`
- `jmeter\results\<opt-name>-iter2-report`
- `jmeter\results\<opt-name>-iter3-report`

### Step 4.7: Stop Gateway

```powershell
taskkill /F /IM java.exe
```

### Step 4.8: Extract Statistics

Same as Phase 1, Step 1.9, but with the optimization name prefix.

---

## Phase 5: Compare Results

### Step 5.1: Verify Functional Tests Passed

Before comparing performance numbers, check the functional test results from Phase 4.5:

| Functional Test | Baseline | After Optimization | Status |
|----------------|----------|-------------------|--------|
| test_rate_limit_* | ✅ | ? | |
| test_sqli_* | ✅ | ? | |
| test_xss_* | ✅ | ? | |
| test_bot_* | ✅ | ? | |
| test_proxy_* | ✅ | ? | |

**If any functional test regressed → STOP. REVERT the optimization. Do not proceed to performance comparison.**

### Step 5.2: Side-by-Side Performance Comparison

| Metric | Baseline (avg iter 2+3) | Optimization (avg iter 2+3) | Delta | Winner |
|--------|------------------------|---------------------------|-------|--------|
| RPS | | | | |
| Mean Latency | | | | |
| P50 | | | | |
| P90 | | | | |
| P95 | | | | |
| P99 | | | | |
| Error Rate | | | | |

### Step 5.3: Decision Criteria

**KEEP** the optimization if:
- All functional tests pass (same as baseline)
- RPS improved by **>2%** (beyond 5% noise floor, need clear signal)
- OR Mean Latency improved by **>5%**
- AND no metric regressed by more than **2%**

**REVERT** if:
- Any functional test regressed (correctness > performance)
- Any metric regressed by **>2%**
- OR no measurable improvement (delta within ±3% noise floor)
- OR new bugs/errors introduced

### Step 5.4: Statistical Significance

- Calculate variance between iter 2 and 3 for both baseline and optimization
- If variance >5% for either, the test is unreliable — note this in the report

---

## Phase 6: Decision

### Step 6.1: If KEEP

```powershell
# Switch to v2 and merge
git checkout v2
git merge opt/<optimization-name> --no-ff -m "perf: <description>"
# Update OPTIMIZATION-TRACKER.md
```

### Step 6.2: If REVERT

```powershell
# Delete the feature branch, stay on v2
git checkout v2
git branch -D opt/<optimization-name>
# Update OPTIMIZATION-TRACKER.md with ❌ result
```

---

## Phase 7: Report

### Step 7.1: Create Report File

Create `jmeter/reports/optimization-reports/<opt-name>-report.md` with:

```markdown
# <Optimization Name> — Test Report

**Date:** <date>
**Optimization:** <what was changed>
**Files Modified:** <list>
**Expected Impact:** <from tracker>
**Actual Result:** <RPS delta, latency delta>

## Baseline (V2)
| Metric | Iter 2 | Iter 3 | Average |
|--------|--------|--------|---------|
| RPS | | | |
| Mean | | | |
| P50 | | | |
| P99 | | | |

## After Optimization
| Metric | Iter 2 | Iter 3 | Average |
|--------|--------|--------|---------|
| RPS | | | |
| Mean | | | |
| P50 | | | |
| P99 | | | |

## Comparison
| Metric | Baseline | After | Delta | Verdict |
|--------|----------|-------|-------|---------|
| RPS | | | | ✅/❌ |
| Mean | | | | ✅/❌ |
| P50 | | | | ✅/❌ |
| P99 | | | | ✅/❌ |

## Verdict: ✅ KEEP / ❌ REVERT
<explanation>

## Why It Worked / Didn't Work
<root cause analysis>
```

### Step 7.2: Update OPTIMIZATION-TRACKER.md

In the **Results Summary** table, add the new row:

```markdown
| **V9-<name>** | <description> | <RPS> | <Mean> | ✅/❌ <verdict> |
```

If REVERTED, also add to the **❌ DO NOT REPEAT** table with the reason.

If KEPT, move the optimization from **Future Plan** to **⚠️ Already Applied (Keep)**.

### Step 7.3: Commit

```powershell
git add -A jmeter/reports/optimization-reports/
git commit -m "docs: <opt-name> test report — <keep/revert>"
```

### Step 7.4: Return to v2

```powershell
git checkout v2
```

---

## Phase 8: Loop

Repeat from Phase 2 with the next optimization in the queue.

Stop when:
- All Tier 1 optimizations are tried
- OR user intervenes
- OR 3 consecutive optimizations show no improvement (suggest infrastructure changes)

---

## Quick Reference: File Locations

| Item | Path |
|------|------|
| Tracker | `jmeter/reports/optimization-reports/OPTIMIZATION-TRACKER.md` |
| Reports | `jmeter/reports/optimization-reports/<name>-report.md` |
| JMeter test plan | `jmeter/01-basic-load-test.jmx` |
| JMeter results | `jmeter/results/` |
| Gateway code | `gateway/src/main/java/com/waf/gateway/` |
| Gateway config | `gateway/src/main/resources/application.yml` |
| Build script | `gateway/build.gradle.kts` |
| Dockerfile | `Dockerfile.gateway` |
| Redis config | `RedisConfig.java` — `gateway/src/main/java/com/waf/gateway/config/` |
| Functional tests | `tests/test_waf_gateway.py` |
| Test config | `tests/config.py` — `DEFAULT_HEADERS` with browser UA |
| Test fixtures | `tests/conftest.py` — auto-patches UA to avoid bot detection |

## Quick Reference: Key Services

| Service | File | Purpose | Redis Commands |
|---------|------|---------|---------------|
| RateLimitService | `service/RateLimitService.java` | IP rate limiting | ZADD, ZCARD, EXPIRE, ZREMRANGEBYSCORE |
| BotDetectionService | `service/BotDetectionService.java` | Bot scoring | ZADD, ZCARD, EXPIRE, HGETALL |
| WafService | `service/WafService.java` | Request orchestration | — |
| MetricsService | `service/MetricsService.java` | Metrics collection | — |
| KafkaEventPublisher | `service/KafkaEventPublisher.java` | Event publishing | — |
| SqlInjectionFilter | `service/SqlInjectionFilter.java` | SQL injection detection | — |
| XssFilter | `service/XssFilter.java` | XSS detection | — |

## Quick Reference: Redis Keys Per Request

Each WAF request triggers these Redis operations:

1. **Rate limit check** (RateLimitService.isAllowed):
   - ZREMRANGEBYSCORE `rate_limit:<ip>:<path>` 0 <windowStart>
   - ZCARD `rate_limit:<ip>:<path>`
   - ZADD `rate_limit:<ip>:<path>` <now> <now>
   - EXPIRE `rate_limit:<ip>:<path>` 60

2. **Bot detection** (BotDetectionService.recordRequest):
   - ZADD `bot:requests:<ip>` <now> <now>
   - EXPIRE `bot:requests:<ip>` 60

3. **Bot frequency check** (BotDetectionService.getRequestCountLastMinute):
   - ZCARD `bot:requests:<ip>`

4. **IP reputation** (BotDetectionService.analyzeIpReputation):
   - HGETALL `ip:reputation:<ip>`

**Total: 8 Redis roundtrips per request** — this is the optimization target.
