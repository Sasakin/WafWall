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


@pytest.fixture(autouse=True, scope="function")
def browser_user_agent():
    """Patch requests.get/post to use browser User-Agent instead of python-requests.
    
    python-requests contains 'requests' string which is in KNOWN_BOTS list,
    causing WAF to block all test requests as bots.
    """
    old_get = requests.get
    old_post = requests.post
    old_put = requests.put
    old_delete = requests.delete

    def patched_get(url, **kwargs):
        headers = kwargs.setdefault('headers', {})
        headers.setdefault('User-Agent', config.DEFAULT_HEADERS['User-Agent'])
        headers.setdefault('Accept', config.DEFAULT_HEADERS['Accept'])
        headers.setdefault('Accept-Language', config.DEFAULT_HEADERS['Accept-Language'])
        kwargs.setdefault('timeout', config.TIMEOUT)
        return old_get(url, **kwargs)

    def patched_post(url, **kwargs):
        headers = kwargs.setdefault('headers', {})
        headers.setdefault('User-Agent', config.DEFAULT_HEADERS['User-Agent'])
        headers.setdefault('Accept', config.DEFAULT_HEADERS['Accept'])
        headers.setdefault('Accept-Language', config.DEFAULT_HEADERS['Accept-Language'])
        kwargs.setdefault('timeout', config.TIMEOUT)
        return old_post(url, **kwargs)

    def patched_put(url, **kwargs):
        headers = kwargs.setdefault('headers', {})
        headers.setdefault('User-Agent', config.DEFAULT_HEADERS['User-Agent'])
        kwargs.setdefault('timeout', config.TIMEOUT)
        return old_put(url, **kwargs)

    def patched_delete(url, **kwargs):
        headers = kwargs.setdefault('headers', {})
        headers.setdefault('User-Agent', config.DEFAULT_HEADERS['User-Agent'])
        kwargs.setdefault('timeout', config.TIMEOUT)
        return old_delete(url, **kwargs)

    requests.get = patched_get
    requests.post = patched_post
    requests.put = patched_put
    requests.delete = patched_delete
    yield
    requests.get = old_get
    requests.post = old_post
    requests.put = old_put
    requests.delete = old_delete


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
