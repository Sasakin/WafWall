-- ClickHouse Schema for WAF Security Events
-- Database: security

CREATE DATABASE IF NOT EXISTS security;

-- Main security events table
CREATE TABLE IF NOT EXISTS security.security_events (
    event_id UUID,
    timestamp DateTime64(3, 'UTC'),
    source_ip IPv4,
    user_agent String,
    request_path String,
    request_method String,
    threat_type String,
    threat_score UInt8,
    country_code String,
    is_blocked UInt8,
    response_time_ms UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip, threat_type)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Materialized view: hourly aggregated stats by threat type and country
CREATE MATERIALIZED VIEW IF NOT EXISTS security.hourly_stats_by_threat
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts_hour)
ORDER BY (ts_hour, threat_type, country_code)
AS SELECT
    toStartOfHour(timestamp) AS ts_hour,
    threat_type,
    country_code,
    count() AS total_requests,
    sum(is_blocked) AS blocked_count,
    avg(response_time_ms) AS avg_latency,
    quantile(0.99)(response_time_ms) AS p99_latency
FROM security.security_events
GROUP BY ts_hour, threat_type, country_code;

-- Materialized view: hourly top blocked IPs
CREATE MATERIALIZED VIEW IF NOT EXISTS security.hourly_top_ips
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts_hour)
ORDER BY (ts_hour, source_ip)
AS SELECT
    toStartOfHour(timestamp) AS ts_hour,
    source_ip,
    sum(is_blocked) AS blocked_count,
    count() AS total_requests,
    any(threat_type) AS primary_threat
FROM security.security_events
WHERE is_blocked = 1
GROUP BY ts_hour, source_ip;

-- Materialized view: daily aggregated stats
CREATE MATERIALIZED VIEW IF NOT EXISTS security.daily_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts_date)
ORDER BY (ts_date, threat_type)
AS SELECT
    toDate(timestamp) AS ts_date,
    threat_type,
    count() AS total_requests,
    sum(is_blocked) AS blocked_count,
    uniqExact(source_ip) AS unique_ips,
    avg(response_time_ms) AS avg_latency,
    max(response_time_ms) AS max_latency
FROM security.security_events
GROUP BY ts_date, threat_type;

-- Materialized view: geo distribution by hour
CREATE MATERIALIZED VIEW IF NOT EXISTS security.hourly_geo_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts_hour)
ORDER BY (ts_hour, country_code)
AS SELECT
    toStartOfHour(timestamp) AS ts_hour,
    country_code,
    count() AS total_requests,
    sum(is_blocked) AS blocked_count,
    uniqExact(source_ip) AS unique_ips
FROM security.security_events
WHERE country_code != ''
GROUP BY ts_hour, country_code;

-- Materialized view: rate limit hits per IP per hour
CREATE MATERIALIZED VIEW IF NOT EXISTS security.hourly_rate_limit_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts_hour)
ORDER BY (ts_hour, source_ip)
AS SELECT
    toStartOfHour(timestamp) AS ts_hour,
    source_ip,
    count() AS rate_limit_hits
FROM security.security_events
WHERE threat_type = 'RATE_LIMIT_EXCEEDED'
GROUP BY ts_hour, source_ip;

-- Table for IP blocklist
CREATE TABLE IF NOT EXISTS security.ip_blocklist (
    ip IPv4,
    reason String,
    blocked_at DateTime,
    expires_at DateTime,
    blocked_by String
) ENGINE = MergeTree()
ORDER BY (ip, blocked_at);

-- Table for alerts
CREATE TABLE IF NOT EXISTS security.alerts (
    alert_id UUID,
    timestamp DateTime64(3, 'UTC'),
    source_ip IPv4,
    threat_type String,
    threshold_exceeded UInt32,
    message String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip);

-- Dictionary for known bot User-Agents
CREATE DICTIONARY IF NOT EXISTS security.bot_user_agents (
    user_agent_prefix String,
    bot_name String,
    is_malicious UInt8
) PRIMARY KEY user_agent_prefix
SOURCE(HTTP(URL 'https://example.com/bots.json'))
LAYOUT(flat())
LIFETIME(3600);

-- Create indexes for common queries
ALTER TABLE security.security_events ADD INDEX idx_source_ip source_ip TYPE bloom_filter GRANULARITY 1;
ALTER TABLE security.security_events ADD INDEX idx_threat_type threat_type TYPE set(1000) GRANULARITY 4;
ALTER TABLE security.security_events ADD INDEX idx_country_code country_code TYPE set(1000) GRANULARITY 4;