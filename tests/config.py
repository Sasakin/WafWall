import os

WAF_HOST = os.getenv("WAF_HOST", "localhost")
WAF_PORT = int(os.getenv("WAF_PORT", "8080"))

GATEWAY_URL = f"http://{WAF_HOST}:{WAF_PORT}"

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC_SECURITY_EVENTS = "security.events"
KAFKA_TOPIC_ALERTS = "security.alerts"

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "waf")

ALERT_HOST = os.getenv("ALERT_HOST", "localhost")
ALERT_PORT = int(os.getenv("ALERT_PORT", "8083"))

PROXY_BACKEND_URL = os.getenv("PROXY_BACKEND_URL", "http://localhost:8081")

TIMEOUT = 5
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 100

# Browser User-Agent to avoid bot detection by WAF
# Default python-requests UA contains "requests" which is in KNOWN_BOTS list
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}