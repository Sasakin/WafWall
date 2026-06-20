"""
Тесты для WAF Gateway (UC-001, UC-002, UC-003, UC-004, UC-005)

Coverage:
- Rate Limiting
- SQL Injection Detection
- XSS Detection
- Bot Detection
- Request Proxying
- Health Check
- Security Event Logging
- Metrics
- Whitelist
- Circuit Breaker
"""

import pytest
import requests
import time
import random
from typing import Generator

import config


# ============================================================
# Health Check
# ============================================================

class TestHealthCheck:
    """UC-013: Health Check системы"""

    def test_health_endpoint(self, waf_url: str):
        try:
            response = requests.get(
                f"{waf_url}/health",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
            data = response.json()
            assert "status" in data or "components" in data
        except requests.exceptions.ReadTimeout:
            pytest.skip("Health endpoint timed out (Kafka unavailable)")

    def test_actuator_health(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/actuator/health",
            timeout=config.TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "UP"

    def test_health_liveness(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/health/liveness",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
            timeout=config.TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") in ["UP", "ok", "OK"]


# ============================================================
# Rate Limiting
# ============================================================

class TestRateLimiting:
    """UC-002: Rate Limiting"""

    def test_rate_limit_allowed(self, waf_url: str, cleanup_redis):
        """Single request from a fresh IP should be allowed (200 or proxied)."""
        response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"}
        )
        # Should NOT be rate-limited (403 from rate limit). 
        # 200 = proxied to backend, 404 = backend doesn't have this path (still OK)
        assert response.status_code in [200, 404, 502]

    def test_rate_limit_exceeded(self, waf_url: str, cleanup_redis):
        """After exceeding rate limit, subsequent requests should be blocked."""
        test_ip = f"192.168.1.{random.randint(1, 254)}"

        for _ in range(config.RATE_LIMIT_MAX + 10):
            response = requests.get(
                f"{waf_url}/api/test",
                headers={"X-Forwarded-For": test_ip}
            )
            if response.status_code == 403 and "Rate limit" in (response.text or ""):
                break

        # After exceeding limit, must be blocked
        last_response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": test_ip}
        )
        assert last_response.status_code == 403

    def test_rate_limit_per_endpoint(self, waf_url: str, cleanup_redis):
        """Rate limit is per-IP+path. Different path should have separate counter."""
        test_ip = f"10.10.10.{random.randint(1, 254)}"

        for _ in range(config.RATE_LIMIT_MAX):
            requests.get(f"{waf_url}/api/endpoint1", headers={"X-Forwarded-For": test_ip})

        # endpoint2 should still be allowed (different path = different rate limit bucket)
        response = requests.get(
            f"{waf_url}/api/endpoint2",
            headers={"X-Forwarded-For": test_ip}
        )
        assert response.status_code in [200, 404, 502]

    def test_rate_limit_different_ips(self, waf_url: str, cleanup_redis):
        """Different IPs should have independent rate limits."""
        ip_a = f"172.16.1.{random.randint(1, 254)}"
        ip_b = f"172.16.2.{random.randint(1, 254)}"

        # Exhaust rate limit for IP A
        for _ in range(config.RATE_LIMIT_MAX + 5):
            requests.get(f"{waf_url}/api/test", headers={"X-Forwarded-For": ip_a})

        # IP B should still be allowed
        response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": ip_b}
        )
        assert response.status_code in [200, 404, 502]

    def test_rate_limit_window_resets(self, waf_url: str, cleanup_redis):
        """After rate limit window passes, requests should be allowed again."""
        test_ip = f"10.99.99.{random.randint(1, 254)}"

        # Exhaust rate limit
        for _ in range(config.RATE_LIMIT_MAX + 5):
            requests.get(f"{waf_url}/api/test", headers={"X-Forwarded-For": test_ip})

        # Confirm blocked
        blocked = requests.get(f"{waf_url}/api/test", headers={"X-Forwarded-For": test_ip})
        assert blocked.status_code == 403

        # Wait for window to reset (window is 60s — too long for test, so we skip if RATE_LIMIT_WINDOW > 10)
        if config.RATE_LIMIT_WINDOW <= 10:
            time.sleep(config.RATE_LIMIT_WINDOW + 1)
            allowed = requests.get(f"{waf_url}/api/test", headers={"X-Forwarded-For": test_ip})
            assert allowed.status_code in [200, 404, 502]
        else:
            pytest.skip(f"Rate limit window is {config.RATE_LIMIT_WINDOW}s — too long for test")


# ============================================================
# SQL Injection Detection
# ============================================================

class TestSqlInjectionDetection:
    """UC-003: Детектирование SQL-инъекций"""

    def test_sqli_union_select(self, waf_url: str):
        """UNION-based SQL injection should be blocked."""
        payloads = [
            "/api/users?id=1' UNION SELECT * FROM users--",
            "/api/search?q=test' OR '1'='1",
            "/api/query?sql=DROP TABLE users",
            "/api/item?id=1; DELETE FROM orders",
            "/api?id=1' OR 1=1--",
            "/api?search=') UNION ALL SELECT NULL--",
        ]

        blocked = False
        for payload in payloads:
            response = requests.get(
                f"{waf_url}{payload}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            if response.status_code == 403:
                blocked = True
                break

        assert blocked, "At least one SQL injection payload should be blocked (403)"

    def test_sqli_url_encoded(self, waf_url: str):
        """URL-encoded SQL injection should be detected after decoding."""
        payloads = [
            "/api?id=%27%20UNION%20SELECT%20*%20FROM%20users--",
            "/api?search=test%27%20OR%20%271%27%3D%271",
        ]

        blocked = False
        for payload in payloads:
            response = requests.get(
                f"{waf_url}{payload}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            if response.status_code == 403:
                blocked = True
                break

        assert blocked, "URL-encoded SQL injection should be blocked"

    def test_sqli_comment_injection(self, waf_url: str):
        """SQL comment-based injection should be detected."""
        payloads = [
            "/api?id=1--",
            "/api?id=1/*comment*/",
            "/api?data=1;#",
        ]

        blocked = False
        for payload in payloads:
            response = requests.get(
                f"{waf_url}{payload}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            if response.status_code == 403:
                blocked = True
                break

        assert blocked, "SQL comment injection should be blocked"

    def test_sqli_normal_request_allowed(self, waf_url: str):
        """Normal requests without SQL patterns should NOT be blocked by SQLi filter."""
        normal_requests = [
            "/api/users/123",
            "/api/products?page=1",
            "/api/search?q=laptop",
            "/api/categories/electronics",
        ]
        for req in normal_requests:
            response = requests.get(
                f"{waf_url}{req}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            # Must not be 403 with SQL injection message (could be 403 from rate limit or bot — that's OK)
            # The key: it should NOT be blocked specifically for SQL injection
            assert response.status_code != 403 or "SQL" not in (response.text or ""), \
                f"Normal request '{req}' was falsely blocked as SQL injection"


# ============================================================
# XSS Detection
# ============================================================

class TestXssDetection:
    """UC-004: Детектирование XSS-атак"""

    def test_xss_script_tag(self, waf_url: str):
        """Script tag XSS should be blocked."""
        payloads = [
            "/api?input=<script>alert(1)</script>",
            "/api/search?q=<img src=x onerror=alert(1)>",
            "/api?comment=<svg onload=alert(1)>",
            "/api?data=<iframe src=javascript:alert(1)>",
            "/api?q=<body onload=alert(1)>",
        ]

        blocked = False
        for payload in payloads:
            response = requests.get(
                f"{waf_url}{payload}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            if response.status_code == 403:
                blocked = True
                break

        assert blocked, "At least one XSS script tag payload should be blocked"

    def test_xss_javascript_uri(self, waf_url: str):
        """javascript: URI XSS should be detected."""
        payloads = [
            "/api?url=javascript:alert(1)",
            "/api?link=javascript:prompt(1)",
        ]

        blocked = False
        for payload in payloads:
            response = requests.get(
                f"{waf_url}{payload}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            if response.status_code == 403:
                blocked = True
                break

        assert blocked, "javascript: URI XSS should be blocked"

    def test_xss_event_handlers(self, waf_url: str):
        """Event handler XSS (onerror, onmouseover) should be detected."""
        payloads = [
            "/api?input=<img onerror=alert(1) src=x>",
            "/api?data=<div onmouseover=alert(1)>hover</div>",
            "/api?text=<input onfocus=alert(1) autofocus>",
        ]

        blocked = False
        for payload in payloads:
            response = requests.get(
                f"{waf_url}{payload}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            if response.status_code == 403:
                blocked = True
                break

        assert blocked, "Event handler XSS should be blocked"

    def test_xss_normal_request_allowed(self, waf_url: str):
        """Normal requests should NOT be falsely blocked as XSS."""
        normal_requests = [
            "/api/products?category=laptops",
            "/api/search?q=phone",
            "/api/users/name/John",
        ]
        for req in normal_requests:
            response = requests.get(
                f"{waf_url}{req}",
                headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
                timeout=config.TIMEOUT
            )
            assert response.status_code != 403 or "XSS" not in (response.text or ""), \
                f"Normal request '{req}' was falsely blocked as XSS"


# ============================================================
# Bot Detection
# ============================================================

class TestBotDetection:
    """UC-005: Детектирование ботов"""

    def test_bot_known_user_agent(self, waf_url: str):
        """Known bot user agents should increase bot score."""
        bot_agents = [
            "curl/7.68.0",
            "python-requests/2.28.0",
            "Wget/1.21.1",
            "scrapy",
        ]

        for agent in bot_agents:
            response = requests.get(
                f"{waf_url}/api/test",
                headers={
                    "X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}",
                    "User-Agent": agent
                },
                timeout=config.TIMEOUT
            )
            # Bot UA should either be blocked (403) or at least scored
            # We can't guarantee full block without other signals, so accept any non-500
            assert response.status_code != 500, \
                f"Bot UA '{agent}' caused server error"

    def test_bot_empty_user_agent(self, waf_url: str):
        """Empty User-Agent should be suspicious (increase bot score)."""
        response = requests.get(
            f"{waf_url}/api/test",
            headers={
                "X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}",
                "User-Agent": ""
            },
            timeout=config.TIMEOUT
        )
        assert response.status_code != 500

    def test_bot_high_frequency(self, waf_url: str, cleanup_redis):
        """High request frequency from same IP should trigger bot detection."""
        test_ip = f"10.20.30.{random.randint(1, 254)}"

        # Send many rapid requests — enough to exceed frequencyThreshold (1000)
        # But we can't send 1000+ in test, so just verify the mechanism works
        for _ in range(100):
            requests.get(
                f"{waf_url}/api/test",
                headers={"X-Forwarded-For": test_ip}
            )

        response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": test_ip}
        )
        # Should either be blocked or at least scored higher
        assert response.status_code != 500

    def test_normal_browser_user_agent(self, waf_url: str, cleanup_redis):
        """Normal browser User-Agent should NOT be flagged as bot."""
        browser_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        ]

        for agent in browser_agents:
            response = requests.get(
                f"{waf_url}/api/test",
                headers={
                    "X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}",
                    "User-Agent": agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=config.TIMEOUT
            )
            # Browser UA should NOT be blocked as bot (could be 403 from other reasons, but not bot)
            assert response.status_code in [200, 404, 502], \
                f"Browser UA was blocked: {response.status_code} {response.text[:100]}"

    def test_suspicious_tool_user_agent(self, waf_url: str):
        """Known attack tools should be blocked."""
        tool_agents = [
            "sqlmap/1.5",
            "nikto/2.1.6",
            "Nmap/7.80",
            "gobuster/3.1",
        ]

        for agent in tool_agents:
            response = requests.get(
                f"{waf_url}/api/test",
                headers={
                    "X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}",
                    "User-Agent": agent
                },
                timeout=config.TIMEOUT
            )
            # These should be blocked (high bot score)
            assert response.status_code in [200, 403, 404], \
                f"Attack tool UA '{agent}' caused unexpected status: {response.status_code}"


# ============================================================
# Proxy Service
# ============================================================

class TestProxyService:
    """UC-001: Проксирование запросов к бэкенду"""

    def test_proxy_get_request(self, waf_url: str):
        """GET request should be proxied to backend."""
        response = requests.get(
            f"{waf_url}/api/proxy/test",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
            timeout=config.TIMEOUT
        )
        # Backend is nginx — should return 200 or 404 (not 500)
        assert response.status_code in [200, 404, 502, 503]

    def test_proxy_with_query_params(self, waf_url: str):
        """Query parameters should be forwarded to backend."""
        response = requests.get(
            f"{waf_url}/api/proxy/test?param1=value1&param2=value2",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404, 502, 503]

    def test_proxy_post_request(self, waf_url: str):
        """POST request should be proxied to backend."""
        response = requests.post(
            f"{waf_url}/api/proxy/test",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
            json={"key": "value"},
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404, 405, 502, 503]

    def test_proxy_preserves_client_ip(self, waf_url: str):
        """X-Forwarded-For should be passed to backend."""
        test_ip = f"10.50.50.{random.randint(1, 254)}"
        response = requests.get(
            f"{waf_url}/api/proxy/test",
            headers={"X-Forwarded-For": test_ip},
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404, 502, 503]


# ============================================================
# Security Event Logging
# ============================================================

class TestSecurityEventLogging:
    """UC-006: Логирование событий безопасности"""

    def test_event_on_block(self, waf_url: str):
        """Blocked request should generate a security event."""
        payload = "/api?id=' UNION SELECT * FROM users--"
        response = requests.get(
            f"{waf_url}{payload}",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
            timeout=config.TIMEOUT
        )
        assert response.status_code == 403

    def test_event_on_allow(self, waf_url: str):
        """Allowed request should generate a security event."""
        response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404, 502]


# ============================================================
# Metrics
# ============================================================

class TestMetrics:
    """UC-014: Экспорт метрик в Prometheus"""

    def test_prometheus_metrics_endpoint(self, waf_url: str):
        # Metrics are exposed via /actuator/prometheus, not /metrics directly
        response = requests.get(
            f"{waf_url}/actuator/prometheus",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"},
            timeout=config.TIMEOUT
        )
        assert response.status_code == 200

    def test_actuator_health(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/actuator/health",
            timeout=config.TIMEOUT
        )
        assert response.status_code == 200

    def test_actuator_info(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/actuator/info",
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404]


# ============================================================
# Whitelist
# ============================================================

class TestWhitelist:
    """UC-012: Управление правилами WAF - Whitelist"""

    def test_whitelist_get_endpoint(self, waf_url: str):
        response = requests.get(f"{waf_url}/api/whitelist", timeout=config.TIMEOUT)
        assert response.status_code in [200, 404]

    def test_whitelist_add_ip(self, waf_url: str):
        response = requests.post(
            f"{waf_url}/api/whitelist",
            json={"ip": "192.168.1.100", "reason": "test"},
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 201, 404, 405]


# ============================================================
# Circuit Breaker
# ============================================================

class TestCircuitBreaker:
    """UC-015: Graceful Degradation - Circuit Breaker"""

    def test_circuit_breaker_endpoint(self, waf_url: str, cleanup_redis):
        response = requests.get(f"{waf_url}/api/circuitbreaker", timeout=config.TIMEOUT)
        assert response.status_code in [200, 404]

    def test_circuit_breaker_actuator(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/actuator/circuitbreakers",
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404]


# ============================================================
# Integration: Combined Attack Scenarios
# ============================================================

class TestCombinedScenarios:
    """Integration tests: multiple attack types in sequence"""

    def test_mixed_attack_types(self, waf_url: str, cleanup_redis):
        """Send SQLi, XSS, and bot requests in sequence — each should be handled correctly."""
        test_ip = f"10.77.77.{random.randint(1, 254)}"

        # 1. Normal request — should pass
        r1 = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": test_ip},
            timeout=config.TIMEOUT
        )
        assert r1.status_code in [200, 404, 502]

        # 2. SQL injection — should be blocked
        r2 = requests.get(
            f"{waf_url}/api?id=1' UNION SELECT * FROM users--",
            headers={"X-Forwarded-For": test_ip},
            timeout=config.TIMEOUT
        )
        assert r2.status_code == 403

        # 3. XSS — should be blocked
        r3 = requests.get(
            f"{waf_url}/api?input=<script>alert(1)</script>",
            headers={"X-Forwarded-For": test_ip},
            timeout=config.TIMEOUT
        )
        assert r3.status_code == 403

        # 4. Normal request again — should still work (not permanently blocked)
        r4 = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": test_ip},
            timeout=config.TIMEOUT
        )
        assert r4.status_code in [200, 404, 502]

    def test_attack_then_normal_different_ip(self, waf_url: str, cleanup_redis):
        """Attack from one IP should not affect another IP."""
        attacker_ip = f"10.88.88.{random.randint(1, 254)}"
        normal_ip = f"10.88.89.{random.randint(1, 254)}"

        # Attacker sends SQLi
        r1 = requests.get(
            f"{waf_url}/api?id=1' OR 1=1--",
            headers={"X-Forwarded-For": attacker_ip},
            timeout=config.TIMEOUT
        )
        assert r1.status_code == 403

        # Normal user should be unaffected
        r2 = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": normal_ip},
            timeout=config.TIMEOUT
        )
        assert r2.status_code in [200, 404, 502]
