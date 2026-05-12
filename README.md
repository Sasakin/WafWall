# WAF + Analytics Pipeline + BotDetector

Защита веб-приложений с потоковой аналитикой и детектированием ботов.

## Быстрый старт

### 1. Запуск инфраструктуры

```bash
docker-compose up -d
```

Сервисы:
- Redis: http://localhost:6379
- Kafka: http://localhost:9092
- ClickHouse: http://localhost:8123
- Kafka UI: http://localhost:8085

### 2. Сборка проекта

```bash
gradle build
```

### 3. Запуск сервисов

```bash
# Terminal 1 - WAF Gateway
java -jar gateway/build/libs/gateway.jar

# Terminal 2 - Stream Processor  
java -jar processor/build/libs/processor.jar

# Terminal 3 - Alert Service
java -jar alert/build/libs/alert.jar
```

## Архитектура

```
Client -> WAF Gateway -> Backend
            |
            v
          Kafka
            |
            v
    Stream Processor -> ClickHouse
            |
            v
       Alert Service -> Redis (blocklist)
```

## API Endpoints

### WAF Gateway (port 8080)
- `GET /health` - Health check
- `GET /health/readiness` - Readiness probe
- `GET /api/metrics/system` - System metrics
- `GET /api/metrics/jvm` - JVM metrics
- `GET /metrics` - Prometheus metrics

### Stream Processor (port 8081)
- `GET /health` - Health check

### Alert Service (port 8082)
- `GET /health` - Health check
- `GET /api/alerts/stats` - Alert statistics
- `GET /api/alerts/blocklist` - Blocked IPs
- `POST /api/alerts/block` - Block IP
- `DELETE /api/alerts/block/{ip}` - Unblock IP

## Конфигурация

### Переменные окружения

| Пariable | Default | Description |
|---------|---------|-------------|
| REDIS_HOST | localhost | Redis host |
| REDIS_PORT | 6379 | Redis port |
| KAFKA_BOOTSTRAP_SERVERS | localhost:9092 | Kafka servers |
| CLICKHOUSE_HOST | localhost | ClickHouse host |
| WAF_BACKEND_URL | http://localhost:8090 | Backend URL |

## Мониторинг

### Prometheus метрики

- `waf_requests_total` - Total requests
- `waf_requests_blocked_total` - Blocked requests
- `waf_blocked_total{threat_type}` - By threat type
- `waf_request_duration_seconds` - Request latency

### Grafana дашборды

1. Общий трафик - RPS по времени
2. Угрозы по типам - SQLi, XSS, Bot, DDoS
3. Топ блокированных IP
4. Время обработки фильтров

## Разработка

### Структура проекта

```
wave-wall/
├── common/          # Общие модели
├── gateway/        # WAF Gateway
├── processor/      # Stream Processor
├── alert/          # Alert Service
├── docker-compose.yml
└── clickhouse-init/
```

### Тесты

```bash
gradle test
```

### Линтинг

```bash
gradle check
```

## Лицензия

MIT