# WAF + Analytics Pipeline + BotDetector

Полная документация проекта системы защиты веб-приложений с потоковой аналитикой и детектированием ботов в реальном времени.

---

## Содержание

1. [Общее описание системы](#1-общее-описание-системы)
2. [Архитектура системы](#2-архитектура-системы)
3. [Компоненты системы](#3-компоненты-системы)
4. [Потоки данных](#4-потоки-данных)
5. [Реализация ключевых функций](#5-реализация-ключевых-функций)
6. [Мониторинг и метрики](#6-мониторинг-и-метрики)
7. [Масштабирование и отказоустойчивость](#7-масштабирование-и-отказоустойчивость)
8. [Статус реализации](#8-статус-реализации)
9. [План развития](#9-план-развития)
10. [Use Cases](#10-use-cases)
11. [Риски и митигация](#11-риски-и-митигация)
12. [Критерии успеха](#12-критерии-успеха)

---

## 1. Общее описание системы

### 1.1 Цель проекта

Разработка распределённой системы защиты веб-приложений от атак (WAF) с потоковой аналитикой и детектированием ботов в реальном времени.

### 1.2 Ключевые требования

| Требование | Значение |
|------------|----------|
| Пропускная способность | 100,000+ RPS на узел |
| Задержка фильтрации | < 5ms (p99) |
| Доступность | 99.9% |
| Время детектирования атаки | < 1 секунды |
| Хранение аналитики | 30+ дней |

---

## 2. Архитектура системы

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET / CLIENTS                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           LOAD BALANCER (Nginx/HAProxy)                         │
│                         L7 балансировка + SSL termination                       │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                     ┌───────────────────┼───────────────────┐
                     ▼                   ▼                   ▼
         ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
         │   WAF Gateway #1  │ │   WAF Gateway #2  │ │   WAF Gateway #N  │
         │   (Spring Boot)    │ │   (Spring Boot)   │ │   (Spring Boot)   │
         │                   │ │                   │ │                   │
         │  • Rate Limiting  │ │  • Rate Limiting  │ │  • Rate Limiting  │
         │  • SQLi/XSS Check │ │  • SQLi/XSS Check │ │  • SQLi/XSS Check │
         │  • Bot Detection  │ │  • Bot Detection  │ │  • Bot Detection  │
         │  • Redis Cache    │ │  • Redis Cache    │ │  • Redis Cache    │
         └─────────┬──────────┘ └─────────┬──────────┘ └─────────┬──────────┘
                   │                      │                      │
                   └──────────────────────┼──────────────────────┘
                                         │
                     ┌───────────────────┼───────────────────┐
                     ▼                   ▼                   ▼
         ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
         │     Kafka         │ │     Kafka         │ │     Kafka         │
         │  (Security Logs)  │ │  (Analytics)      │ │  (Alerts)         │
         └─────────┬──────────┘ └─────────┬──────────┘ └─────────┬──────────┘
                   │                      │                      │
                   ▼                       ▼                      ▼
         ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
         │   ClickHouse      │ │   Stream Processor│ │   Alert Service   │
         │   (Analytics DB)  │ │   (Spring Boot)   │ │   (Spring Boot)   │
         └─────────┬──────────┘ └─────────┬──────────┘ └─────────┬──────────┘
                   │                      │                      │
                   └──────────────────────┼──────────────────────┘
                                         │
                                         ▼
                               ┌───────────────────┐
                               │   Grafana +       │
                               │   Prometheus      │
                               │   (Monitoring)    │
                               └───────────────────┘
```

### 2.1 Архитектурные слои

| Слой | Компоненты |
|------|------------|
| **Edge Layer** | Nginx/HAProxy (Load Balancer) |
| **Security & Processing Layer** | WAF Gateway, Stream Processor, Alert Service |
| **Data Layer** | Redis (Cache), Kafka (Messaging), ClickHouse (Analytics) |
| **Monitoring Layer** | Prometheus, Grafana |

---

## 3. Компоненты системы

### 3.1 WAF Gateway

**Технологии:** Spring Boot 3, Spring WebFlux, Redis

**Ответственность:**
- Приём всех входящих HTTP-запросов
- Синхронная фильтрация (SQLi, XSS, паттерны атак)
- Rate Limiting через Redis
- Детектирование ботов по поведенческим паттернам
- Асинхронная отправка логов в Kafka

**Структура модулей:**
```
com.waf.gateway
├── WafGatewayApplication.java
├── config/
│   ├── RedisConfig.java
│   ├── KafkaConfig.java
│   └── SecurityConfig.java
├── filter/
│   ├── WafFilter.java
│   ├── RateLimitFilter.java (abstract SecurityFilter)
│   ├── SqlInjectionFilter.java
│   ├── XssFilter.java
│   └── BotDetectionFilter.java
├── service/
│   ├── WafService.java
│   ├── SecurityFilterChain.java
│   ├── BackendClient.java (interface)
│   ├── EventPublisher.java (interface)
│   ├── ProxyService.java
│   ├── BotDetectionService.java
│   ├── RateLimitService.java
│   └── KafkaEventPublisher.java
├── controller/
│   ├── HealthController.java
│   ├── MetricsController.java
│   └── WhitelistController.java
└── model/
    ├── BotAnalysisResult.java
    └── FilterResult.java
```

### 3.2 Stream Processor

**Технологии:** Spring Boot, Kafka Streams / Spring Kafka

**Ответственность:**
- Агрегация событий безопасности
- Выявление сложных атак (DDoS, brute force)
- Обогащение данных (geo-IP, reputation)
- Отправка алертов в Alert Service

**Структура:**
```
com.waf.processor
├── StreamProcessorApplication.java
├── consumer/
│   └── SecurityEventConsumer.java
├── service/
│   ├── ClickHouseWriterService.java
│   ├── EventAggregationService.java
│   ├── AnomalyDetectionService.java
│   └── GeoIpEnrichmentService.java
└── config/
    ├── KafkaConfig.java
    ├── ClickHouseConfig.java
    └── AlertKafkaConfig.java
```

### 3.3 ClickHouse Storage

**Технологии:** ClickHouse, grafana-clickhouse-datasource plugin

**Подключение к Grafana:**
- URL: `http://clickhouse:9000`
- Database: `security`
- Plugin: `grafana-clickhouse-datasource`

**Дашборды Grafana (7 total):**
- **Prometheus (01-04):** Traffic, Threats, Alerts, Latency
- **ClickHouse (05-07):** Analytics, Top IPs, Performance

### 3.4 Alert Service

**Технологии:** Spring Boot, WebSocket, Telegram Bot API

**Ответственность:**
- Генерация алертов при превышении порогов
- WebSocket push-уведомления в реальном времени
- Custom Web Dashboard (port 5000) для мониторинга
- Управление IP blocklist

**Структура:**
```
com.waf.alert
├── AlertServiceApplication.java
├── service/
│   ├── AlertService.java
│   ├── BlocklistService.java
│   └── TelegramNotificationService.java
├── consumer/
│   └── AlertConsumer.java
├── controller/
│   ├── AlertController.java
│   └── HealthController.java
└── config/
    ├── KafkaConfig.java
    ├── RedisConfig.java
    └── WebSocketConfig.java
```

### 3.5 Redis

**Использование:**
- Rate Limiting counters (sliding window)
- IP reputation cache (TTL 1 час)
- Session storage для авторизованных пользователей
- Distributed locks для координации
- IP blocklist

**Структуры данных:**
```
# Rate limiting
rate_limit:{ip}:{endpoint} -> ZSET (timestamp, count)

# IP reputation
ip:reputation:{ip} -> HASH (score, last_seen, threat_count)

# Active blocks
blocked:ip:{ip} -> STRING (TTL until unblock)

# Bot fingerprints
bot:fingerprint:{hash} -> HASH (user_agent, behavior_score)

# Circuit breaker state
circuitbreaker:{service}:state -> STRING (closed/open/half-open)
circuitbreaker:{service}:failures -> COUNTER
```

### 3.6 Kafka Topics

| Topic | Назначение | Partitioning |
|-------|------------|--------------|
| `security.events` | Логи всех запросов | По source_ip |
| `security.alerts` | Алерты об атаках | По alert_type |
| `security.blocklist` | Обновления blocklist | По IP |

---

## 4. Потоки данных

### 4.1 Основной поток запроса

```
1. Клиент → Load Balancer → WAF Gateway
2. WAF Gateway:
   ├─ Проверка Rate Limit (Redis)
   ├─ Проверка SQLi/XSS паттернов
   ├─ Проверка Bot Detection
   ├─ Если угроза → Блокировка + Лог в Kafka
   └─ Если чисто → Проксирование к бэкенду
3. Асинхронно: Лог события → Kafka → ClickHouse
4. Grafana читает из ClickHouse для дашбордов
```

### 4.2 Поток детектирования атаки

```
1. WAF Gateway обнаруживает подозрительный запрос
2. Отправляет событие в Kafka topic: security.events
3. Stream Processor агрегирует события по IP (окно 1 минута)
4. Если порог превышен → Alert в Kafka topic: security.alerts
5. Alert Service отправляет уведомление (WebSocket → Custom Dashboard)
6. IP добавляется в блок-лист Redis (TTL 1 час)
```

---

## 5. Реализация ключевых функций

### 5.1 Rate Limiting (Sliding Window)

```java
@Service
public class RateLimitService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final int WINDOW_SIZE_SECONDS = 60;
    private static final int MAX_REQUESTS_PER_WINDOW = 100;

    public boolean isAllowed(String ip, String endpoint) {
        String key = String.format("rate_limit:%s:%s", ip, endpoint);
        long now = System.currentTimeMillis();
        long windowStart = now - (WINDOW_SIZE_SECONDS * 1000);

        redisTemplate.opsForZSet().removeRangeByScore(key, 0, windowStart);

        Long count = redisTemplate.opsForZSet().zCard(key);

        if (count != null && count >= MAX_REQUESTS_PER_WINDOW) {
            return false;
        }

        redisTemplate.opsForZSet().add(key, String.valueOf(now), now);
        redisTemplate.expire(key, WINDOW_SIZE_SECONDS, TimeUnit.SECONDS);

        return true;
    }
}
```

### 5.2 SQL Injection Detection

```java
@Component
public class SqlInjectionFilter implements SecurityFilter {

    private static final Pattern SQLI_PATTERN = Pattern.compile(
        "(?i)(union\\s+select|drop\\s+table|insert\\s+into|" +
        "delete\\s+from|update\\s+.*\\s+set|--|/\\*|\\*/|" +
        "';\\s*--|\\bor\\s+1\\s*=\\s*1|\\band\\s+1\\s*=\\s*1)"
    );

    @Override
    public FilterResult check(HttpServletRequest request) {
        if (containsSqlInjection(request)) {
            return block("SQL injection pattern detected");
        }
        return pass();
    }

    public boolean containsSqlInjection(HttpServletRequest request) {
        // Implementation with URL decode
    }
}
```

### 5.3 Bot Detection

```java
@Service
public class BotDetectionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final int BOT_THRESHOLD = 70;

    public BotScore analyzeBotBehavior(String ip, HttpServletRequest request) {
        BotScore score = new BotScore();

        analyzeUserAgent(request, score);       // +25-30 penalty
        analyzeFrequency(ip, score);             // +15-35 penalty
        analyzeNavigation(request, score);       // +15 penalty
        analyzeJsCookie(request, score);        // +10 penalty
        analyzeIpReputation(ip, score);          // +20 penalty
        analyzeHeaders(request, score);          // +15 penalty
        recordRequest(ip);

        return score;
    }

    public boolean isBot(BotScore score) {
        return score.getTotalScore() >= BOT_THRESHOLD;
    }
}
```

### 5.4 Kafka Producer

```java
@Service
public class SecurityEventProducer implements EventPublisher {

    private static final String TOPIC = "security.events";
    private final KafkaTemplate<String, SecurityEvent> kafkaTemplate;

    @Override
    public void publish(SecurityEvent event) {
        event.setEventId(UUID.randomUUID().toString());
        event.setTimestamp(Instant.now());

        kafkaTemplate.send(TOPIC, event.getSourceIp(), event);
    }
}
```

### 5.5 Filter Chain (SOLID Implementation)

```java
@Component
public class SecurityFilterChain {

    private final List<SecurityFilter> filters;

    public SecurityFilterChain(List<SecurityFilter> filters) {
        this.filters = filters;
    }

    public FilterResult execute(HttpServletRequest request) {
        for (SecurityFilter filter : filters) {
            FilterResult result = filter.check(request);
            if (result.isBlocked()) {
                return result;
            }
        }
        return FilterResult.pass();
    }
}
```

---

## 6. Мониторинг и метрики

### 6.1 Prometheus Метрики

| Метрика | Тип | Описание |
|---------|-----|-----------|
| `waf_requests_total` | Counter | Всего запросов |
| `waf_blocks_total` | Counter | Заблокированные запросы по типам угроз |
| `waf_rate_limit_hits_total` | Counter | Срабатывания rate limiting |
| `waf_request_duration_seconds` | Histogram | Время обработки |
| `waf_filter_duration_seconds` | Histogram | Время каждого фильтра |
| `waf_bot_detection_score` | Gauge | Текущий score бота |

### 6.2 Grafana Дашборды

1. **Общий трафик** — RPS по времени
2. **Угрозы по типам** — SQLi, XSS, Bot, DDoS
3. **Топ блокированных IP** — гео-распределение
4. **Время обработки фильтров** — p50, p95, p99
5. **Алерты за период** — количество и серьёзность

---

## 7. Масштабирование и отказоустойчивость

### 7.1 Горизонтальное масштабирование

| Компонент | Стратегия |
|-----------|-----------|
| WAF Gateway | Stateless, Kubernetes HPA по CPU/RPS |
| Kafka | 3+ брокера, репликация factor=3 |
| Redis | Cluster mode, 6 нод (3 master + 3 replica) |
| ClickHouse | 2+ шарда, репликация через ZooKeeper |

### 7.2 Circuit Breaker (Resilience4j)

```yaml
resilience4j.circuitbreaker:
  instances:
    redisBackend:
      slidingWindowSize: 10
      failureRateThreshold: 50
      waitDurationInOpenState: 10000
    kafkaBackend:
      slidingWindowSize: 10
      failureRateThreshold: 50
      waitDurationInOpenState: 5000
```

### 7.3 Fallback стратегии

| Компонент | Fallback |
|-----------|----------|
| Redis недоступен | Локальный in-memory rate limiting |
| Kafka недоступен | Буферизация в локальную очередь |
| ClickHouse недоступен | Queue для отложенной записи |
| Backend недоступен | Return 502 Bad Gateway |

---

## 8. Статус реализации

### ✅ Готово

| Компонент | Описание |
|----------|----------|
| Docker Compose | Redis, Kafka, ClickHouse, Kafka UI |
| ClickHouse Schema | Таблицы security_events, alerts, ip_blocklist |
| WAF Gateway | Фильтрация SQLi, XSS |
| Rate Limiting | Sliding window через Redis |
| Proxy Service | Проксирование к бэкенду |
| Prometheus Метрики | Counters, Timers, Gauges |
| Health Checks | Проверка Redis, Kafka |
| Bot Detection | Поведенческий анализ |
| Whitelist Service | Белый список IP и путей |
| Circuit Breaker | Отказоустойчивость |

### 📋 В разработке

| Компонент | Статус |
|-----------|--------|
| WebSocket + Dashboard UI | ✅ Готово |
| Grafana дашборды | Требует настройки |
| Нагрузочное тестирование | Не проводилось |

> **Примечание:** Telegram Bot заменён на WebSocket + HTML Dashboard для упрощения тестирования дипломного проекта.

---

## 9. План развития (12 недель)

### Фаза 1: Базовая функциональность

| Неделя | Задачи | Статус |
|--------|--------|--------|
| 1 | Docker Compose, ClickHouse schema, Redis/Kafka/ClickHouse | ✅ |
| 2 | Расширение SQLi/XSS фильтров, Path Traversal | 🔄 |
| 3 | IP reputation, Fallback при недоступности Redis | 🔄 |

### Фаза 2: Расширенная защита

| Неделя | Задачи | Статус |
|--------|--------|--------|
| 4 | Bot Detection - поведенческий анализ, JS cookie, Frequency | ✅ |
| 5 | Whitelist, in-memory rate limiting, retry логика Kafka | ✅ |
| 6 | Circuit Breaker (Resilience4j), fallback стратегии | ✅ |

### Фаза 3: Stream Processor

| Неделя | Задачи | Статус |
|--------|--------|--------|
| 7 | Агрегация событий (окно 1 минута), GeoIP обогащение, ClickHouse batch inserts | ✅ |
| 8 | DDoS Detection (>50 блокировок/мин), Brute-force Detection (>10 попыток) | ✅ |

### Фаза 4: Alert Service

| Неделя | Задачи | Статус |
|--------|--------|--------|
| 9 | Alert Receiver, WebSocket UI | ✅ |

| **Alert Recipient** | Получатель уведомлений об атаках (через WebSocket, Custom Dashboard) |

### 10.2 Основные Use Cases

| ID | Название | Описание |
|----|----------|----------|
| UC-001 | Фильтрация запроса | Проверка запроса через все фильтры |
| UC-002 | Rate Limiting | Ограничение 100 запросов в минуту на IP |
| UC-003 | SQLi Detection | Обнаружение SQL-инъекций по паттернам |
| UC-004 | XSS Detection | Обнаружение XSS-атак |
| UC-005 | Bot Detection | Детектирование ботов по поведению (score >= 70) |
| UC-006 | Логирование событий | Запись всех событий в Kafka |
| UC-007 | Потоковая обработка | Агрегация и обогащение событий |
| UC-008 | Генерация алертов | Создание уведомлений об атаках |
| UC-009 | Блокировка IP | Динамическая блокировка IP в Redis |
| UC-010 | Просмотр дашборда | Мониторинг в Grafana |
| UC-011 | Анализ инцидентов | Исторический анализ в ClickHouse |
| UC-012 | Управление правилами | Настройка whitelist и правил |
| UC-013 | Health Check | Проверка здоровья компонентов |
| UC-014 | Экспорт метрик | Prometheus metrics endpoint |
| UC-015 | Graceful Degradation | Работа при недоступности зависимостей |

---

## 11. Риски и митигация

| Риск | Вероятность | Митигация |
|------|-------------|-----------|
| Слишком широкий скоуп | Высокая | Фокус на MVP: WAF + Kafka + ClickHouse |
| Сложность настройки ClickHouse | Средняя | Использовать Docker image, минимальная конфигурация |
| Недостаточная производительность | Средняя | Нагрузочное тестирование, оптимизация индексов |
| Ложные срабатывания WAF | Высокая | Tunable правила, whitelist для тестовых IP |

---

## 12. Критерии успеха

1. **Демо в реальном времени** — показать блокировку атаки с визуализацией в Grafana
2. **Нагрузочное тестирование** — JMeter скрипты, графики до/после оптимизаций
3. **Архитектурная документация** — C4 диаграммы, sequence diagrams
4. **Trade-offs обоснование** — почему Kafka, а не RabbitMQ; почему ClickHouse, а не Elasticsearch
5. **Код на GitHub** — чистая структура, тесты, CI/CD pipeline

---

## Структура проекта

```
wave-wall/
├── common/                    # Общие модели и интерфейсы
│   └── src/main/java/com/waf/common/
│       ├── model/             # SecurityEvent, ThreatType, BotScore, Alert, Rule
│       └── repository/        # SecurityEventRepository, RateLimitRepository
│
├── gateway/                   # WAF Gateway сервис
│   └── src/main/java/com/waf/gateway/
│       ├── config/            # Redis, Kafka конфигурация
│       ├── filter/            # SecurityFilter, SecurityFilterChain, FilterRegistry
│       ├── service/           # WafService, ProxyService, BotDetection, RateLimit
│       ├── controller/        # Health, Metrics, Whitelist контроллеры
│       └── model/             # BotAnalysisResult, FilterResult
│
├── processor/                 # Stream Processor сервис
│   └── src/main/java/com/waf/processor/
│       ├── consumer/          # SecurityEventConsumer
│       ├── service/           # ClickHouseWriter, EventAggregation, AnomalyDetection
│       └── config/            # Kafka, ClickHouse конфигурация
│
├── alert/                     # Alert Service сервис
│   └── src/main/java/com/waf/alert/
│       ├── consumer/          # AlertConsumer
│       ├── service/          # AlertService, BlocklistService, TelegramNotification
│       ├── controller/        # AlertController
│       └── config/           # Kafka, Redis, WebSocket конфигурация
│
├── tests/                       # Python тесты
│   ├── config.py             # Конфигурация тестов
│   ├── conftest.py           # Pytest fixtures
│   ├── test_waf_gateway.py   # Тесты WAF Gateway
│   ├── test_stream_processor.py  # Тесты Stream Processor
│   ├── test_alert_service.py # Тесты Alert Service
│   └── test_infrastructure.py   # Тесты инфраструктуры
│
├── docker-compose.yml         # Docker Compose конфигурация
├── build.gradle.kts           # Gradle build файл
├── REFACTORING_PLAN.md       # План рефакторинга
└── PROJECT_DOCUMENTATION.md  # Этот документ
```