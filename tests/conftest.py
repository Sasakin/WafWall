import pytest
import redis
import requests
import time
from typing import Generator
import config


@pytest.fixture(scope="session")
def redis_client() -> Generator[redis.Redis, None, None]:
    client = redis.Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        decode_responses=True,
        socket_connect_timeout=config.TIMEOUT
    )
    try:
        client.ping()
    except redis.ConnectionError:
        pytest.skip("Redis is not available")

    yield client
    client.flushdb()


@pytest.fixture(scope="session")
def waf_url() -> str:
    return config.GATEWAY_URL


@pytest.fixture(scope="function")
def cleanup_redis(redis_client):
    redis_client.flushdb()
    yield
    redis_client.flushdb()


@pytest.fixture(scope="session")
def check_services() -> dict:
    services = {}

    try:
        response = requests.get(f"{config.GATEWAY_URL}/health", timeout=config.TIMEOUT)
        services["gateway"] = response.status_code == 200
    except:
        services["gateway"] = False

    try:
        client = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, socket_connect_timeout=config.TIMEOUT)
        services["redis"] = client.ping()
    except:
        services["redis"] = False

    try:
        client = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT + 1, socket_connect_timeout=config.TIMEOUT)
        services["kafka"] = client.ping()
    except:
        services["kafka"] = False

    try:
        response = requests.get(f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/ping", timeout=config.TIMEOUT)
        services["clickhouse"] = response.status_code == 200
    except:
        services["clickhouse"] = False

    return services


def is_service_available(service_name: str, check_services: dict) -> bool:
    if service_name not in check_services or not check_services[service_name]:
        pytest.skip(f"{service_name} is not available")
    return True