-- Test data for development and testing

-- Insert sample security events
INSERT INTO security.security_events VALUES
    (generateUUID(), now(), toIPv4('192.168.1.100'), 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '/api/users', 'GET', 'UNKNOWN', 0, 'US', 0, 45),
    (generateUUID(), now(), toIPv4('10.0.0.50'), 'curl/7.68.0', '/api/login', 'POST', 'SQL_INJECTION', 100, 'XX', 1, 12),
    (generateUUID(), now(), toIPv4('172.16.0.25'), 'python-requests/2.28.0', '/admin', 'GET', 'BOT_DETECTED', 85, 'US', 1, 8),
    (generateUUID(), now(), toIPv4('8.8.8.8'), 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)', '/api/posts', 'GET', 'UNKNOWN', 0, 'US', 0, 120);

-- Insert sample alerts
INSERT INTO security.alerts VALUES
    (generateUUID(), now(), toIPv4('10.0.0.50'), 'SQL_INJECTION', 25, 'Multiple SQL injection attempts detected'),
    (generateUUID(), now(), toIPv4('172.16.0.25'), 'BOT_DETECTED', 15, 'Automated bot traffic detected');

-- Insert sample blocked IPs
INSERT INTO security.ip_blocklist VALUES
    (toIPv4('10.0.0.100'), 'Manual block', now(), now() + 3600, 'admin'),
    (toIPv4('192.168.99.99'), 'DDoS attack', now(), now() + 7200, 'system');