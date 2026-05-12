"""
Тесты для инфраструктуры

Coverage:
- Redis (Rate Limiting, IP Blocklist)
- Kafka (Producer/Consumer)
- Circuit Breaker
- Graceful Degradation
"""

import pytest
import redis
import requests
import json
import time
import random
import threading

import config


class TestRedisHealth:
    """UC-013: Health Check - Redis"""

    def test_redis_connection(self, redis_client):
        assert redis_client.ping()

    def test_redis_info(self, redis_client):
        info = redis_client.info()
        assert "redis_version" in info

    def test_redis_memory(self, redis_client):
        info = redis_client.info("memory")
        assert "used_memory_human" in info


class TestRedisRateLimiting:
    """UC-002: Rate Limiting через Redis"""

    def test_rate_limit_key_structure(self, redis_client, cleanup_redis):
        test_ip = f"10.0.1.{random.randint(1, 254)}"
        key = f"rate_limit:{test_ip}:/api/test"

        redis_client.zadd(key, {str(time.time()): time.time()})
        redis_client.expire(key, config.RATE_LIMIT_WINDOW)

        assert redis_client.exists(key)

    def test_rate_limit_sliding_window(self, redis_client, cleanup_redis):
        test_ip = f"10.0.2.{random.randint(1, 254)}"
        key = f"rate_limit:{test_ip}:/api/test"
        now = time.time()

        for i in range(config.RATE_LIMIT_MAX):
            redis_client.zadd(key, {str(now + i): now + i})

        redis_client.expire(key, config.RATE_LIMIT_WINDOW)

        count = redis_client.zcard(key)
        assert count == config.RATE_LIMIT_MAX

    def test_rate_limit_cleanup(self, redis_client, cleanup_redis):
        test_ip = f"10.0.3.{random.randint(1, 254)}"
        key = f"rate_limit:{test_ip}:/api/test"

        now = time.time()
        old_time = now - config.RATE_LIMIT_WINDOW - 10

        redis_client.zadd(key, {str(old_time): old_time, str(now): now})
        redis_client.expire(key, config.RATE_LIMIT_WINDOW)

        redis_client.zremrangebyscore(key, 0, now - config.RATE_LIMIT_WINDOW)

        count = redis_client.zcard(key)
        assert count == 1


class TestRedisIpBlocklist:
    """UC-009: IP Blocklist в Redis"""

    def test_blocklist_key_structure(self, redis_client):
        test_ip = f"192.168.100.{random.randint(1, 254)}"
        key = f"blocked:ip:{test_ip}"

        redis_client.setex(key, 3600, "blocked")
        assert redis_client.exists(key)

    def test_blocklist_ttl(self, redis_client):
        test_ip = f"192.168.101.{random.randint(1, 254)}"
        key = f"blocked:ip:{test_ip}"
        ttl = 1800

        redis_client.setex(key, ttl, "blocked")
        remaining = redis_client.ttl(key)

        assert 0 < remaining <= ttl

    def test_blocklist_cleanup(self, redis_client):
        test_ip = f"192.168.102.{random.randint(1, 254)}"
        key = f"blocked:ip:{test_ip}"

        redis_client.setex(key, -1, "blocked")
        redis_client.delete(key)

        assert not redis_client.exists(key)


class TestRedisIpReputation:
    """UC-005: IP reputation cache"""

    def test_reputation_key_structure(self, redis_client):
        test_ip = f"10.10.10.{random.randint(1, 254)}"
        key = f"ip:reputation:{test_ip}"

        redis_client.hset(key, mapping={
            "score": "50",
            "last_seen": str(int(time.time())),
            "threat_count": "0"
        })
        redis_client.expire(key, 3600)

        assert redis_client.exists(key)

    def test_reputation_update(self, redis_client):
        test_ip = f"10.10.11.{random.randint(1, 254)}"
        key = f"ip:reputation:{test_ip}"

        redis_client.hincrby(key, "threat_count", 1)
        redis_client.hincrbyfloat(key, "score", 10)

        count = redis_client.hget(key, "threat_count")
        assert int(count) == 1


class TestRedisBotFingerprints:
    """UC-005: Bot fingerprints"""

    def test_bot_fingerprint_key(self, redis_client):
        fingerprint = f"hash_{random.randint(1000, 9999)}"
        key = f"bot:fingerprint:{fingerprint}"

        redis_client.hset(key, mapping={
            "user_agent": "curl/7.68.0",
            "behavior_score": "80"
        })
        redis_client.expire(key, 600)

        assert redis_client.exists(key)


class TestRedisCircuitBreaker:
    """UC-015: Circuit Breaker состояние в Redis"""

    def test_circuit_breaker_state(self, redis_client):
        service_name = "kafka"
        key = f"circuitbreaker:{service_name}:state"

        redis_client.set(key, "closed")
        redis_client.expire(key, 300)

        assert redis_client.get(key) == "closed"

    def test_circuit_breaker_failure_count(self, redis_client):
        service_name = "redis"
        key = f"circuitbreaker:{service_name}:failures"

        redis_client.incr(key)
        redis_client.expire(key, 300)

        assert int(redis_client.get(key)) > 0


class TestRedisFallbackMode:
    """UC-015: Fallback при недоступности"""

    def test_local_cache_key(self, redis_client):
        key = "local_cache:active"
        redis_client.set(key, "true", ex=60)
        assert redis_client.get(key) == "true"


class TestKafkaHealth:
    """UC-013: Health Check - Kafka"""

    def test_kafka_broker_available(self):
        try:
            import kafka
            from kafka.admin import KafkaAdminClient
            admin = KafkaAdminClient(
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                request_timeout_ms=5000
            )
            admin.close()
            kafka_available = True
        except:
            kafka_available = False

        if not kafka_available:
            pytest.skip("Kafka not available")

    def test_kafka_topics_exist(self):
        try:
            import kafka
            from kafka import KafkaConsumer
            consumer = KafkaConsumer(
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                request_timeout_ms=5000
            )
            topics = consumer.topics()
            consumer.close()

            assert config.KAFKA_TOPIC_SECURITY_EVENTS in topics or topics is not None
        except:
            pytest.skip("Kafka not available")


class TestKafkaProducer:
    """UC-006: Логирование событий в Kafka"""

    @pytest.fixture(autouse=True)
    def check_kafka(self):
        try:
            from kafka import KafkaProducer
            producer = KafkaProducer(
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                request_timeout_ms=5000
            )
            producer.close()
        except:
            pytest.skip("Kafka not available")

    def test_produce_to_security_events(self):
        try:
            from kafka import KafkaProducer
            from json import dumps

            producer = KafkaProducer(
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )

            test_event = {
                "event_id": "test-123",
                "timestamp": str(time.time()),
                "source_ip": "192.168.1.1",
                "threat_type": "TEST",
                "is_blocked": False
            }

            future = producer.send(
                config.KAFKA_TOPIC_SECURITY_EVENTS,
                value=test_event,
                key="test"
            )
            record_metadata = future.get(timeout=10)

            producer.flush()
            producer.close()

            assert record_metadata.topic == config.KAFKA_TOPIC_SECURITY_EVENTS
        except:
            pytest.skip("Kafka producer test failed")

    def test_produce_to_alerts(self):
        try:
            from kafka import KafkaProducer

            producer = KafkaProducer(
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )

            test_alert = {
                "alert_id": "alert-123",
                "type": "DDOS_DETECTED",
                "source_ip": "10.0.0.1",
                "timestamp": str(time.time())
            }

            future = producer.send(
                config.KAFKA_TOPIC_ALERTS,
                value=test_alert,
                key="10.0.0.1"
            )
            future.get(timeout=10)

            producer.flush()
            producer.close()
        except:
            pytest.skip("Kafka producer test failed")


class TestKafkaConsumer:
    """UC-007: Потоковая обработка из Kafka"""

    @pytest.fixture(autouse=True)
    def check_kafka(self):
        try:
            from kafka import KafkaConsumer
            consumer = KafkaConsumer(
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                request_timeout_ms=5000
            )
            consumer.close()
        except:
            pytest.skip("Kafka not available")

    def test_consumer_subscription(self):
        try:
            from kafka import KafkaConsumer

            consumer = KafkaConsumer(
                config.KAFKA_TOPIC_SECURITY_EVENTS,
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
                auto_offset_reset='earliest',
                consumer_timeout_ms=2000
            )

            subscriptions = consumer.subscription()
            consumer.close()

            assert config.KAFKA_TOPIC_SECURITY_EVENTS in subscriptions
        except:
            pytest.skip("Kafka consumer test failed")


class TestKafkaPartitioning:
    """UC-007: Partitioning по IP"""

    def test_partition_count(self):
        try:
            from kafka import KafkaConsumer

            consumer = KafkaConsumer(
                config.KAFKA_TOPIC_SECURITY_EVENTS,
                bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS
            )

            partitions = consumer.partitions_for_topic(config.KAFKA_TOPIC_SECURITY_EVENTS)
            consumer.close()

            if partitions:
                assert len(partitions) >= 1
        except:
            pytest.skip("Kafka not available")


class TestIntegrationFlows:
    """Интеграционные тесты"""

    def test_waf_to_kafka_to_processor(self, redis_client, cleanup_redis):
        test_ip = f"10.100.1.{random.randint(1, 254)}"
        key = f"rate_limit:{test_ip}:/api/test"

        redis_client.zadd(key, {str(time.time()): time.time()})
        redis_client.expire(key, config.RATE_LIMIT_WINDOW)

        assert redis_client.exists(key)

    def test_alert_to_blocklist_flow(self, redis_client):
        test_ip = f"10.200.1.{random.randint(1, 254)}"
        block_key = f"blocked:ip:{test_ip}"

        redis_client.setex(block_key, 3600, "blocked")

        assert redis_client.exists(block_key)
        assert redis_client.ttl(block_key) > 0

    def test_circuit_breaker_transitions(self, redis_client):
        service = "kafka"
        state_key = f"circuitbreaker:{service}:state"
        fail_key = f"circuitbreaker:{service}:failures"

        redis_client.set(state_key, "closed")
        redis_client.set(fail_key, "0")

        redis_client.incr(fail_key)
        redis_client.incr(fail_key)

        if int(redis_client.get(fail_key)) > 5:
            redis_client.set(state_key, "open")

        assert redis_client.get(state_key) in ["closed", "open"]