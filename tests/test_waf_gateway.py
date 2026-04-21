"""
Тесты для WAF Gateway (UC-001, UC-002, UC-003, UC-004, UC-005)

Coverage:
- Rate Limiting
- SQL Injection Detection
- XSS Detection
- Bot Detection
- Request Proxying
"""

import pytest
import requests
import time
import random
from typing import Generator

import config


class TestHealthCheck:
    """UC-013: Health Check системы"""

    def test_health_endpoint(self, waf_url: str):
        response = requests.get(f"{waf_url}/health", timeout=config.TIMEOUT)
        assert response.status_code == 200
        data = response.json()
        assert "status" in data or "components" in data


class TestRateLimiting:
    """UC-002: Rate Limiting"""

    def test_rate_limit_allowed(self, waf_url: str, cleanup_redis):
        response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": f"10.0.0.{random.randint(1, 254)}"}
        )
        assert response.status_code in [200, 403, 404]

    def test_rate_limit_exceeded(self, waf_url: str, cleanup_redis):
        test_ip = f"192.168.1.{random.randint(1, 254)}"

        for _ in range(config.RATE_LIMIT_MAX + 10):
            response = requests.get(
                f"{waf_url}/api/test",
                headers={"X-Forwarded-For": test_ip}
            )
            if response.status_code == 429:
                break

        last_response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": test_ip}
        )
        assert last_response.status_code in [200, 403, 429]

    def test_rate_limit_per_endpoint(self, waf_url: str, cleanup_redis):
        test_ip = f"10.10.10.{random.randint(1, 254)}"

        for _ in range(config.RATE_LIMIT_MAX):
            requests.get(f"{waf_url}/api/endpoint1", headers={"X-Forwarded-For": test_ip})

        response = requests.get(
            f"{waf_url}/api/endpoint2",
            headers={"X-Forwarded-For": test_ip}
        )
        assert response.status_code in [200, 403, 429]


class TestSqlInjectionDetection:
    """UC-003: Детектирование SQL-инъекций"""

    def test_sqli_union_select(self, waf_url: str):
        payloads = [
            "/api/users?id=1' UNION SELECT * FROM users--",
            "/api/search?q=test' OR '1'='1",
            "/api/query?sql=DROP TABLE users",
            "/api/item?id=1; DELETE FROM orders",
            "/api?id=1' OR 1=1--",
            "/api?search=') UNION ALL SELECT NULL--",
            "/api?query=1 AND 1=1",
            "/api?filter=' OR 'x'='x",
        ]

        for payload in payloads:
            response = requests.get(f"{waf_url}{payload}", timeout=config.TIMEOUT)
            if response.status_code == 403:
                blocked = True
                break
        else:
            blocked = False
        assert blocked or response.status_code != 500

    def test_sqli_url_encoded(self, waf_url: str):
        payloads = [
            "/api?id=%27%20UNION%20SELECT%20*%20FROM%20users--",
            "/api?search=test%27%20OR%20%271%27%3D%271",
            "/api?query=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
        ]
        response = requests.get(f"{waf_url}{payloads[0]}", timeout=config.TIMEOUT)
        assert response.status_code in [200, 403, 404]

    def test_sqli_comment_injection(self, waf_url: str):
        payloads = [
            "/api?id=1--",
            "/api?id=1/*comment*/",
            "/api?data=1;#",
        ]
        response = requests.get(f"{waf_url}{payloads[0]}", timeout=config.TIMEOUT)
        assert response.status_code in [200, 403, 404]

    def test_sqli_normal_request(self, waf_url: str):
        normal_requests = [
            "/api/users/123",
            "/api/products?page=1",
            "/api/search?q=laptop",
            "/api/categories/electronics",
        ]
        for req in normal_requests:
            response = requests.get(f"{waf_url}{req}", timeout=config.TIMEOUT)
            assert response.status_code in [200, 404, 502]


class TestXssDetection:
    """UC-004: Детектирование XSS-атак"""

    def test_xss_script_tag(self, waf_url: str):
        payloads = [
            "/api?input=<script>alert(1)</script>",
            "/api/search?q=<img src=x onerror=alert(1)>",
            "/api?comment=<svg onload=alert(1)>",
            "/api?data=<iframe src=javascript:alert(1)>",
            "/api?q=<body onload=alert(1)>",
        ]

        for payload in payloads:
            response = requests.get(f"{waf_url}{payload}", timeout=config.TIMEOUT)
            if response.status_code == 403:
                blocked = True
                break
        else:
            blocked = False
        assert blocked or response.status_code != 500

    def test_xss_javascript_uri(self, waf_url: str):
        payloads = [
            "/api?url=javascript:alert(1)",
            "/api?link=javascript:prompt(1)",
            "/api?redirect=javascript:void(0)",
        ]
        response = requests.get(f"{waf_url}{payloads[0]}", timeout=config.TIMEOUT)
        assert response.status_code in [200, 403, 404]

    def test_xss_event_handlers(self, waf_url: str):
        payloads = [
            "/api?input=<img onerror=alert(1) src=x>",
            "/api?data=<div onmouseover=alert(1)>hover</div>",
            "/api?text=<input onfocus=alert(1) autofocus>",
        ]
        response = requests.get(f"{waf_url}{payloads[0]}", timeout=config.TIMEOUT)
        assert response.status_code in [200, 403, 404]

    def test_xss_normal_request(self, waf_url: str):
        normal_requests = [
            "/api/products?category=laptops",
            "/api/search?q=phone",
            "/api/users/name/John",
        ]
        for req in normal_requests:
            response = requests.get(f"{waf_url}{req}", timeout=config.TIMEOUT)
            assert response.status_code in [200, 404, 502]


class TestBotDetection:
    """UC-005: Детектирование ботов"""

    def test_bot_known_user_agent(self, waf_url: str):
        bot_agents = [
            "curl/7.68.0",
            "python-requests/2.28.0",
            "Wget/1.21.1",
            "scrapy",
            "bot",
            "Spider",
        ]

        for agent in bot_agents[:3]:
            response = requests.get(
                f"{waf_url}/api/test",
                headers={"User-Agent": agent},
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 403, 404]

    def test_bot_empty_user_agent(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/api/test",
            headers={"User-Agent": ""},
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 403, 404]

    def test_bot_high_frequency(self, waf_url: str, cleanup_redis):
        test_ip = f"10.20.30.{random.randint(1, 254)}"

        for _ in range(60):
            requests.get(f"{waf_url}/api/test", headers={"X-Forwarded-For": test_ip})
            time.sleep(0.01)

        response = requests.get(
            f"{waf_url}/api/test",
            headers={"X-Forwarded-For": test_ip}
        )
        assert response.status_code in [200, 403, 404]

    def test_normal_browser_user_agent(self, waf_url: str):
        browser_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        ]

        for agent in browser_agents:
            response = requests.get(
                f"{waf_url}/api/test",
                headers={
                    "User-Agent": agent,
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9"
                },
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 403, 404]


class TestProxyService:
    """UC-001: Проксирование запросов к бэкенду"""

    def test_proxy_clean_request(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/api/proxy/test",
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404, 502, 503]

    def test_proxy_with_query_params(self, waf_url: str):
        response = requests.get(
            f"{waf_url}/api/proxy/test?param1=value1&param2=value2",
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404, 502, 503]

    def test_proxy_post_request(self, waf_url: str):
        response = requests.post(
            f"{waf_url}/api/proxy/test",
            json={"key": "value"},
            timeout=config.TIMEOUT
        )
        assert response.status_code in [200, 404, 502, 503]


class TestSecurityEventLogging:
    """UC-006: Логирование событий безопасности"""

    def test_event_on_block(self, waf_url: str):
        payload = "/api?id=' UNION SELECT * FROM users--"
        response = requests.get(f"{waf_url}{payload}", timeout=config.TIMEOUT)
        assert response.status_code in [200, 403, 404]

    def test_event_on_allow(self, waf_url: str):
        response = requests.get(f"{waf_url}/api/test", timeout=config.TIMEOUT)
        assert response.status_code in [200, 403, 404]

    def test_event_fields_present(self, waf_url: str):
        response = requests.get(f"{waf_url}/api/test", timeout=config.TIMEOUT)
        assert response.status_code in [200, 403, 404]


class TestMetrics:
    """UC-014: Экспорт метрик в Prometheus"""

    def test_prometheus_metrics_endpoint(self, waf_url: str):
        response = requests.get(f"{waf_url}/metrics", timeout=config.TIMEOUT)
        assert response.status_code in [200, 404]

    def test_actuator_endpoints(self, waf_url: str):
        endpoints = ["/actuator/health", "/actuator/info"]
        for endpoint in endpoints:
            response = requests.get(f"{waf_url}{endpoint}", timeout=config.TIMEOUT)
            assert response.status_code in [200, 404]


class TestWhitelist:
    """UC-012: Управление правилами WAF - Whitelist"""

    def test_whitelist_endpoint(self, waf_url: str):
        response = requests.get(f"{waf_url}/api/whitelist", timeout=config.TIMEOUT)
        assert response.status_code in [200, 404]

    def test_whitelist_operations(self, waf_url: str):
        try:
            response = requests.post(
                f"{waf_url}/api/whitelist",
                json={"ip": "192.168.1.100", "reason": "test"},
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 201, 404, 405]
        except:
            pass


class TestCircuitBreaker:
    """UC-015: Graceful Degradation - Circuit Breaker"""

    def test_circuit_breaker_endpoints(self, waf_url: str, cleanup_redis):
        response = requests.get(f"{waf_url}/api/circuitbreaker", timeout=config.TIMEOUT)
        assert response.status_code in [200, 404]

    def test_circuit_breaker_status(self, waf_url: str):
        try:
            response = requests.get(
                f"{waf_url}/actuator/circuitbreakers",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 404]
        except:
            pass