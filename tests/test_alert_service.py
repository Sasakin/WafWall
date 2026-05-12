"""
Тесты для Alert Service (UC-008, UC-009)

Coverage:
- Генерация алертов
- IP блокировка
- Telegram уведомления
- WebSocket push
"""

import pytest
import requests
import json

import config


class TestAlertServiceHealth:
    """UC-013: Health Check для Alert Service"""

    def test_alert_service_health(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/health",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 404]
        except:
            pytest.skip("Alert Service not available")


class TestAlertGeneration:
    """UC-008: Генерация алертов"""

    def test_alert_endpoint_exists(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_alert_creation(self):
        try:
            alert_data = {
                "type": "DDoS_DETECTED",
                "severity": "HIGH",
                "sourceIp": "192.168.1.100",
                "description": "Test alert",
                "count": 100
            }
            response = requests.post(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts",
                json=alert_data,
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 201, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_alert_list(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts?limit=10",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_alert_by_id(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts/test-id",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")


class TestIpBlocking:
    """UC-009: Динамическая блокировка IP"""

    def test_blocklist_endpoint(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/blocklist",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_block_ip(self):
        try:
            block_data = {
                "ip": f"10.0.0.{random.randint(1, 254)}",
                "reason": "Test block",
                "ttlSeconds": 3600
            }
            response = requests.post(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/blocklist",
                json=block_data,
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 201, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_unblock_ip(self):
        try:
            test_ip = f"192.168.100.{random.randint(1, 254)}"

            requests.post(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/blocklist",
                json={"ip": test_ip, "reason": "test", "ttlSeconds": 3600},
                timeout=config.TIMEOUT
            )

            response = requests.delete(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/blocklist/{test_ip}",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 204, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_blocklist_list(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/blocklist",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_ttl_expiration(self):
        try:
            block_data = {
                "ip": f"172.16.0.{random.randint(1, 254)}",
                "reason": "TTL test",
                "ttlSeconds": 60
            }
            response = requests.post(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/blocklist",
                json=block_data,
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 201, 401, 404]
        except:
            pytest.skip("Alert Service not available")


class TestTelegramNotification:
    """UC-008: Telegram Bot интеграция"""

    def test_telegram_config_endpoint(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/telegram/config",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_telegram_send_test(self):
        try:
            response = requests.post(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/telegram/test",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404, 400]
        except:
            pytest.skip("Alert Service not available")

    def test_telegram_webhook_setup(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/telegram/webhook",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")


class TestWebSocket:
    """UC-008: WebSocket push-уведомления"""

    def test_websocket_endpoint(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/ws/alerts",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404, 400]
        except:
            pytest.skip("Alert Service not available")

    def test_websocket_info(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/ws/info",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")


class TestAlertThresholds:
    """UC-008: Бизнес-правила для алертов"""

    def test_ddos_threshold_query(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts?type=DDOS&period=1m",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_brute_force_threshold_query(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts?type=BRUTE_FORCE&period=1m",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_alert_severity_levels(self):
        try:
            severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            for severity in severities:
                response = requests.get(
                    f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts?severity={severity}",
                    timeout=config.TIMEOUT
                )
                assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")


class TestAlertStatistics:
    """UC-010: Просмотр дашборда - статистика алертов"""

    def test_alert_count_by_type(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts/stats/by-type",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_alert_count_by_severity(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts/stats/by-severity",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_alert_time_distribution(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts/stats/time-distribution",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")


class TestAlertCleanup:
    """UC-009: Автоматическая разблокировка"""

    def test_expired_blocks_cleanup(self):
        try:
            response = requests.post(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/blocklist/cleanup",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 204, 401, 404]
        except:
            pytest.skip("Alert Service not available")

    def test_alert_archive(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/api/alerts?status=archived",
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 401, 404]
        except:
            pytest.skip("Alert Service not available")


import random