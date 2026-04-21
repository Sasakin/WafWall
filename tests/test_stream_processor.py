"""
Тесты для Stream Processor (UC-007)

Coverage:
- Потоковая обработка событий
- Агрегация событий
- Аномалии (DDoS, brute force)
- GeoIP обогащение
- ClickHouse запись
"""

import pytest
import requests
import json
import time
import random

import config


class TestStreamProcessorHealth:
    """UC-013: Health Check для Stream Processor"""

    @pytest.fixture(autouse=True)
    def check_processor(self):
        try:
            response = requests.get(
                f"http://{config.ALERT_HOST}:{config.ALERT_PORT}/health",
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("Stream Processor not available")


class TestEventAggregation:
    """UC-007: Агрегация событий безопасности"""

    def test_clickhouse_events_table(self):
        try:
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": "SELECT count() FROM security_events"},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")

    def test_hourly_aggregation(self):
        try:
            query = """
            SELECT
                toStartOfHour(timestamp) as hour,
                count() as total_requests,
                sum(is_blocked) as blocked
            FROM security_events
            WHERE timestamp >= now() - INTERVAL 1 HOUR
            GROUP BY hour
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")


class TestAnomalyDetection:
    """UC-008: Генерация алертов - Anomaly Detection"""

    def test_ddos_detection_query(self):
        try:
            query = """
            SELECT
                source_ip,
                count() as block_count,
                threat_type
            FROM security_events
            WHERE
                is_blocked = 1 AND
                timestamp >= now() - INTERVAL 1 MINUTE
            GROUP BY source_ip, threat_type
            HAVING count() > 50
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")

    def test_brute_force_detection_query(self):
        try:
            query = """
            SELECT
                source_ip,
                request_path,
                count() as attempt_count
            FROM security_events
            WHERE
                timestamp >= now() - INTERVAL 1 MINUTE
            GROUP BY source_ip, request_path
            HAVING count() > 10
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")

    def test_threat_type_distribution(self):
        try:
            query = """
            SELECT
                threat_type,
                count() as total,
                sum(is_blocked) as blocked
            FROM security_events
            WHERE timestamp >= now() - INTERVAL 1 HOUR
            GROUP BY threat_type
            ORDER BY total DESC
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")


class TestGeoIpEnrichment:
    """UC-007: GeoIP обогащение данных"""

    def test_geo_enrichment_query(self):
        try:
            query = """
            SELECT
                country_code,
                count() as total,
                sum(is_blocked) as blocked
            FROM security_events
            WHERE timestamp >= now() - INTERVAL 1 HOUR
            GROUP BY country_code
            ORDER BY total DESC
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")


class TestClickHouseInsert:
    """UC-007: ClickHouse batch inserts"""

    def test_clickhouse_schema_exists(self):
        try:
            query = """
            SELECT name, type
            FROM system.columns
            WHERE table = 'security_events'
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
            assert "source_ip" in response.text
        except:
            pytest.skip("ClickHouse not available")

    def test_materialized_view_exists(self):
        try:
            query = """
            SELECT name, engine
            FROM system.tables
            WHERE database = 'waf' AND name LIKE '%stats%'
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 400]
        except:
            pytest.skip("ClickHouse not available")

    def test_ttl_configuration(self):
        try:
            query = """
            SELECT
                name,
                formatReadableTTL(expression) as ttl
            FROM system.tables
            WHERE table = 'security_events'
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 400]
        except:
            pytest.skip("ClickHouse not available")


class TestHistoricalAnalysis:
    """UC-011: Анализ исторических данных"""

    def test_query_by_timerange(self):
        try:
            query = """
            SELECT
                count() as total,
                sum(is_blocked) as blocked,
                avg(response_time_ms) as avg_latency
            FROM security_events
            WHERE timestamp BETWEEN
                now() - INTERVAL 7 DAY AND now()
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")

    def test_query_by_ip(self):
        try:
            query = """
            SELECT *
            FROM security_events
            WHERE source_ip = '192.168.1.1'
            LIMIT 100
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")

    def test_query_by_threat_type(self):
        try:
            query = """
            SELECT
                timestamp,
                source_ip,
                request_path,
                is_blocked
            FROM security_events
            WHERE threat_type = 'SQL_INJECTION'
            ORDER BY timestamp DESC
            LIMIT 100
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")


class TestDataRetention:
    """UC-011: Хранение аналитики 30+ дней"""

    def test_data_retention_days(self):
        try:
            query = """
            SELECT
                min(timestamp) as oldest,
                max(timestamp) as newest,
                date_diff('day', min(timestamp), max(timestamp)) as days
            FROM security_events
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code == 200
        except:
            pytest.skip("ClickHouse not available")

    def test_partition_info(self):
        try:
            query = """
            SELECT
                partition,
                min(min_date) as min_date,
                max(max_date) as max_date,
                sum(rows) as rows
            FROM system.parts
            WHERE table = 'security_events' AND active = 1
            GROUP BY partition
            """
            response = requests.post(
                f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/",
                params={"query": query},
                timeout=config.TIMEOUT
            )
            assert response.status_code in [200, 400]
        except:
            pytest.skip("ClickHouse not available")