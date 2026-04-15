# 📐 System Design: WAF + Analytics Pipeline + BotDetector

---

## 🗺 Маршрут проектирования
```
1. Введение
2. Система и требования  
3. Core Entities & API
4. High-Level Design
5. Deep Dives
```

---

## 1. Введение

### Сервис
**Распределённая система защиты веб-приложений (WAF)** с потоковой аналитикой и детектированием ботов в реальном времени.

### Цель
Фильтрация вредоносного трафика с задержкой **< 5ms (p99)** при нагрузке **100,000+ RPS**, сбор метрик безопасности и автоматическое реагирование на атаки.

### Контекст

```plantuml
@startuml Context
title Контекст системы
skinparam backgroundColor #FFFFFF

actor "Клиент / Атакующий" as Client
boundary "WAF System" as WAF_System
boundary "Protected Backend" as Backend
agent "Security Admin" as Admin
database "Grafana/Prometheus" as Monitor

Client --> WAF_System : HTTP/HTTPS запросы
WAF_System --> Backend : Проксирование чистых запросов
WAF_System --> Backend : Блокировка угроз (403)
Admin --> WAF_System : Управление правилами
WAF_System --> Monitor : Метрики и алерты
Monitor --> Admin : Визуализация

note right of WAF_System
  **SLA:**
  • Задержка < 5ms (p99)
  • Доступность 99.9%
  • Детектирование < 1с
end note
@enduml
```

---

## 2. Система и требования

### Функциональные требования ✅
| # | Требование | Описание |
|---|-----------|----------|
| F1 | Фильтрация запросов | Проверка на SQLi, XSS, известные паттерны атак |
| F2 | Rate Limiting | Ограничение запросов по IP и эндпоинту (sliding window) |
| F3 | Bot Detection | Анализ User-Agent, частоты, навигации, JS-cookie |
| F4 | Асинхронное логирование | Отправка событий в Kafka без блокировки основного потока |
| F5 | Агрегация и алертинг | Выявление DDoS/brute-force по окнам времени |
| F6 | Динамическая блокировка | Автоматическое добавление IP в блок-лист Redis |
| F7 | Визуализация | Дашборды в Grafana (RPS, блокировки, топ-угрозы) |
| F8 | Hot-reload правил | Обновление конфигурации без перезапуска |

### Нефункциональные требования ⚡
| Требование | Значение | Обоснование |
|-----------|----------|-------------|
| Пропускная способность | `100,000+ RPS` на узел | Пиковые нагрузки, масштабирование |
| Задержка фильтрации | `< 5 ms (p99)` | Не влиять на UX защищаемого бэкенда |
| Доступность | `99.9%` | Бизнес-критичность защиты |
| Время детектирования атаки | `< 1 секунды` | Быстрое реагирование на инциденты |
| Хранение аналитики | `30+ дней` | Расследования, аудит, тренды |

### 🚫 Out of Scope
```
• L3/L4 DDoS mitigation (сетевой уровень)
• Обучение ML-моделей для классификации трафика
• Аутентификация пользователей защищаемого бэкенда
• Бэкапы, CI/CD, мониторинг инфраструктуры бэкенда
```

---

## 3. Core Entities & API

### Core Entities
```plantuml
@startuml Entities
title Core Entities
skinparam classAttributeIconSize 0

class SecurityEvent {
  +UUID eventId
  +Instant timestamp
  +String sourceIp
  +String userAgent
  +String requestPath
  +ThreatType threatType
  +Integer threatScore
  +Boolean isBlocked
  +Integer responseTimeMs
}

enum ThreatType {
  SQL_INJECTION
  XSS_ATTACK
  BOT_DETECTED
  DDOS_PATTERN
  RATE_LIMIT_EXCEEDED
}

class BotScore {
  +Integer userAgentPenalty
  +Integer frequencyPenalty
  +Integer navigationPenalty
  +Integer jsCookiePenalty
  +Integer getTotalScore()
}

class Alert {
  +UUID alertId
  +String sourceIp
  +ThreatType threatType
  +Integer thresholdExceeded
  +Instant timestamp
}

class Rule {
  +String pattern
  +Integer threshold
  +Duration ttl
  +Action action
}

SecurityEvent "1" *-- "1" ThreatType
SecurityEvent "1" *-- "0..1" BotScore
Alert "1" *-- "1" ThreatType
@enduml
```

### API Контракты

#### Management API (WAF Gateway)
```http
# Health Check
GET /health
→ 200 OK
{
  "status": "UP",
  "components": {
    "redis": "UP",
    "kafka": "UP", 
    "clickhouse": "UP"
  }
}

# Prometheus Metrics
GET /metrics
→ text/plain; version=0.0.4
# HELP waf_requests_total Total filtered requests
# TYPE waf_requests_total counter
waf_requests_total{method="GET",threat_type="none"} 15234

# Правила фильтрации
GET /rules
→ 200 OK
[
  {"id": "sqli-001", "pattern": "(?i)union.*select", "action": "BLOCK"},
  {"id": "rate-ip", "threshold": 100, "window": "60s", "action": "THROTTLE"}
]

PUT /rules
Content-Type: application/json
→ 204 No Content (hot-reload)
```

#### Kafka Contracts (Async Events)
```yaml
# Topic: security.events
key: source_ip (String)
value: 
  eventId: UUID
  timestamp: DateTime64(3)
  sourceIp: String
  userAgent: String
  requestPath: String
  threatType: LowCardinality(String)
  threatScore: UInt8
  isBlocked: Boolean
  responseTimeMs: UInt32

# Topic: security.alerts  
key: alert_id (UUID)
value:
  alertId: UUID
  sourceIp: String
  threatType: String
  thresholdExceeded: UInt32
  timestamp: DateTime64(3)
```

#### Data Flow Interfaces (внутренние)
```http
// Bot Detection
POST /internal/analyze
→ BotScore { totalScore: 75, isBot: true }

// IP Blocklist Management
POST /internal/block
Body: { "ip": "192.168.1.1", "ttl": 3600 }
→ 204 No Content (Redis: blocked:ip:{hash})
```

---

## 4. High-Level Design

### Архитектурная схема
```plantuml
@startuml HLD
title High-Level Architecture
skinparam packageStyle rectangle
skinparam backgroundColor #FEFEFE
skinparam monochrome false

package "Edge Layer" #E8F5E9 {
  component "Load Balancer\n(Nginx/HAProxy)" as LB
  component "WAF Gateway Cluster\n(Spring Boot x N)" as WAF
  database "Redis Cluster\n(Rate Limit + Blocklist)" as Redis
}

package "Streaming Layer" #FFF9C4 {
  component "Kafka Cluster\n(security.events, security.alerts)" as Kafka
  component "Stream Processor\n(Kafka Streams)" as Stream
}

package "Storage & Alerting" #FFEBEE {
  database "ClickHouse Cluster\n(OLAP, 30 days)" as CH
  component "Alert Service\n(Spring Boot)" as Alert
  component "Grafana" as External
}

package "Backend Service" #E3F2FD {
  component "Protected API" as Backend
}

agent "Prometheus" as Prom

' === Основной поток (синхронный) ===
LB --> WAF : HTTP/HTTPS
WAF --> Redis : 1. Rate Limit & Block Check
WAF --> WAF : 2. SQLi/XSS/Bot Filters
WAF --> Backend : 3. Clean Request (Proxy)
WAF --> Kafka : 4. Async Event Log

' === Аналитический поток (асинхронный) ===
Kafka --> Stream : Consume security.events
Stream --> Stream : Aggregate (1-min window)
Stream --> CH : Write Analytics
Stream --> Alert : Threshold Exceeded?

' === Алертинг ===
Alert --> Redis : Update Blocklist (TTL)
Alert --> External : Push Notification

' === Мониторинг ===
Prom --> LB : Scrape /metrics
Prom --> WAF
Prom --> Stream
Prom --> Redis : Exporter
Prom --> Kafka : Exporter
Prom --> CH : Exporter

note right of WAF
  **Критический путь:**
  • Задержка < 5ms (p99)
  • Все проверки in-memory / Redis
  • Fallback при сбоях
end note

note right of Stream
  **Обработка:**
  • Tumbling window: 1 min
  • GeoIP enrichment
  • Pattern detection
end note
@enduml
```

### Основные потоки данных

#### 🔹 Поток 1: Фильтрация запроса (синхронный)
```plantuml
@startuml Flow1
title Поток 1: Обработка входящего запроса
autonumber
skinparam backgroundColor #FFFFFF

actor "Клиент" as Client
participant "Load Balancer" as LB
participant "WAF Gateway" as WAF
database "Redis" as Redis
queue "Kafka" as Kafka
participant "Backend" as Backend

Client -> LB : HTTP Request
LB -> WAF : Forward

activate WAF
WAF -> Redis : Check Rate Limit (ZSET)
activate Redis
Redis --> WAF : Count: 45/100 ✓
deactivate Redis

WAF -> WAF : SQLi Pattern Check
WAF -> WAF : XSS Pattern Check  
WAF -> WAF : Bot Detection Score

alt Угроза обнаружена
  WAF -> Kafka : Publish security.events
  activate Kafka
  Kafka --> WAF : Ack
  deactivate Kafka
  WAF --> Client : HTTP 403 Forbidden
else Запрос чистый
  WAF -> Kafka : Publish security.events (async)
  activate Kafka
  Kafka --> WAF : Ack
  deactivate Kafka
  WAF -> Backend : Proxy Request
  activate Backend
  Backend --> WAF : HTTP 200
  deactivate Backend
  WAF --> Client : HTTP 200
end
deactivate WAF
@enduml
```

#### 🔹 Поток 2: Аналитика и алертинг (асинхронный)
```plantuml
@startuml Flow2
title Поток 2: Детектирование атаки и алертинг
autonumber
skinparam backgroundColor #FFFFFF

queue "Kafka" as Kafka
participant "Stream Processor" as Stream
database "Redis" as Redis
database "ClickHouse" as CH
participant "Alert Service" as Alert
participant "Grafana" as External

Kafka -> Stream : Consume security.events
activate Stream

Stream -> Stream : Aggregate by IP (1-min window)
Stream -> Stream : GeoIP + Reputation Enrich
Stream -> Stream : Check Thresholds

alt Превышен порог атаки
  Stream -> Kafka : Publish security.alerts
  activate Kafka
  Kafka --> Stream : Ack
  deactivate Kafka
  
  Kafka -> Alert : Consume security.alerts
  activate Alert
  Alert -> Redis : Set blocked:ip:{hash} (TTL 1h)
  activate Redis
  Redis --> Alert : OK
  deactivate Redis
  Alert -> External : Push Notification
  deactivate Alert
else Аномалий нет
  Stream -> CH : INSERT security_events
  activate CH
  CH --> Stream : OK
  deactivate CH
end
deactivate Stream
@enduml
```

---

## 5. Deep Dives

### 🔹 Проблема 1: Низкая задержка при 100k+ RPS

**Контекст:**  
Проверка Rate Limiting и правил в центральной БД добавляет задержку. При пике синхронные запросы к Redis могут превысить лимит `< 5ms (p99)`.

**Trade-offs:**
| Вариант | Плюсы | Минусы | Выбор |
|---------|-------|--------|-------|
| Синхронный Redis | Консистентность | Задержка ~10-20ms | ❌ |
| Локальный in-memory | Задержка <1ms | Нет консистентности между нодами | ❌ |
| **Redis + local cache** | Баланс задержки и консистентности | Сложнее инвалидация | ✅ |

**Решение:**
```plantuml
@startuml Solution1
title Решение: Кэширование + Fallback
skinparam backgroundColor #FFFFFF

participant "WAF Gateway" as WAF
database "Redis" as Redis
participant "Local Cache" as Cache

WAF -> Cache : Check local rate limit
activate Cache

alt Cache hit & under limit
  Cache --> WAF : Allow + increment
  WAF -> WAF : Async sync to Redis
else Cache miss or near limit
  WAF -> Redis : Check authoritative count
  activate Redis
  Redis --> WAF : Current count
  deactivate Redis
  WAF -> Cache : Update local state
end
deactivate Cache

alt Redis unavailable
  WAF -> WAF : Fallback to local-only mode
  note right: Graceful Degradation\n(возможны ложные срабатывания)
end
@enduml
```

---

### 🔹 Проблема 2: Consistency of Matching (единая блокировка в кластере)

**Контекст:**  
WAF работает в кластере из N нод. Нужно гарантировать:
1. Атака не будет пропущена из-за рассинхрона между нодами
2. Один IP не получит дублирующие алерты/блокировки

**Trade-offs:**
| Подход | Консистентность | Задержка | Сложность | Выбор |
|--------|----------------|----------|-----------|-------|
| Синхронная блокировка | Высокая | +20-50ms | Низкая | ❌ |
| **Асинхронная через Kafka** | Eventual (<1s) | ~0ms | Средняя | ✅ |
| Distributed Lock (Redis) | Высокая | +10-30ms | Высокая | ❌ |

**Решение:**
```plantuml
@startuml Solution2
title Решение: Eventual Consistency через Kafka
autonumber
skinparam backgroundColor #FFFFFF

participant "Атакующий" as Attacker
participant "WAF Node A" as W1
participant "WAF Node B" as W2
queue "Kafka" as Kafka
participant "Stream Processor" as Stream
database "Redis" as Redis

== Фаза 1: Независимое детектирование ==
Attacker -> W1 : Malicious Request #1
W1 -> W1 : Detect & Block (403)
W1 -> Kafka : security.events (IP=X, threat=SQLi)

Attacker -> W2 : Malicious Request #2  
W2 -> W2 : Detect & Block (403)
W2 -> Kafka : security.events (IP=X, threat=SQLi)

note over W1, W2
  Ноды работают независимо.
  Синхронная координация НЕ требуется.
  Основной путь сохраняет <5ms.
end note

== Фаза 2: Агрегация и принятие решения ==
Kafka -> Stream : Consume events (window: 1 min)
activate Stream
Stream -> Stream : Aggregate by IP
Stream -> Stream : Count blocks: 100/min

alt Threshold exceeded (>50/min)
  Stream -> Kafka : security.alerts (idempotent key)
  Kafka -> Stream : Ack
end
deactivate Stream

== Фаза 3: Распространение блокировки ==
Kafka -> Redis : Set blocked:ip:{hash} (TTL 1h)
activate Redis
Redis --> Kafka : OK
deactivate Redis

== Фаза 4: Единая защита ==
Attacker -> W1 : Request #101
W1 -> Redis : Check blocklist
activate Redis  
Redis --> W1 : BLOCKED
deactivate Redis
W1 --> Attacker : HTTP 403 (Blocklist Match)
@enduml
```

**Ключевые механизмы:**
1. **Idempotent ключи в Kafka** — `alert_id = hash(IP + threat_type + window_start)`
2. **Дедупликация на Consumer** — проверка `processed_alerts` set в Redis
3. **TTL блок-листа** — автоматическая разблокировка, снижение нагрузки на админа
4. **Локальный кэш блок-листа** — проверка `blocked:ip:*` с TTL 5s в памяти WAF

---

### 🔹 Проблема 3: Масштабирование хранения аналитики

**Контекст:**  
При 100k RPS и 10% блокировок → ~10,000 events/sec → ~864M events/day. Традиционные БД не справляются с:
- Записью под высокой нагрузкой
- OLAP-запросами для дашбордов
- Авто-очисткой данных за 30 дней

**Trade-offs:**
| Хранилище | Запись | OLAP | TTL | Стоимость | Выбор |
|-----------|--------|------|-----|-----------|-------|
| PostgreSQL |  Медленно |  | Ручной | Высокая |  ❌|
| Elasticsearch |  Хорошо |  Хорошо |  Сложно | Очень высокая | ❌ |
| **ClickHouse** |  Отлично |  Отлично |  Native | Низкая |  ✅ |

**Решение:**
```plantuml
@startuml Solution3
title Решение: ClickHouse для OLAP-аналитики
skinparam backgroundColor #FFFFFF

package "ClickHouse Cluster" {
  database "Shard 1\n(Replica A + B)" as CH1
  database "Shard 2\n(Replica A + B)" as CH2
  component "ZooKeeper\n(Координация)" as ZK
}

component "Stream Processor" as Stream

Stream --> CH1 : INSERT (shard by hash(IP))
Stream --> CH2 : INSERT

CH1 <--> ZK : Репликация метаданных
CH2 <--> ZK

note right of CH1
  **Движок:** MergeTree
  **PARTITION BY:** toYYYYMM(timestamp)
  **ORDER BY:** (timestamp, source_ip, threat_type)
  **TTL:** timestamp + INTERVAL 30 DAY
end note

note bottom of ZK
  Обеспечивает:
  • Репликацию между репликами
  • Распределение по шардам
  • Deduplication INSERT
end note
@enduml
```

**Схема данных (оптимизированная):**
```sql
-- Основная таблица событий
CREATE TABLE security_events (
    event_id UUID,
    timestamp DateTime64(3, 'UTC'),
    source_ip IPv4,
    user_agent String,
    request_path LowCardinality(String),
    threat_type LowCardinality(String),
    threat_score UInt8,
    country_code LowCardinality(String),
    is_blocked Boolean,
    response_time_ms UInt32
) ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip, threat_type)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Материализованное представление для Grafana
CREATE MATERIALIZED VIEW hourly_stats TO hourly_stats_agg AS
SELECT
    toStartOfHour(timestamp) as ts_hour,
    threat_type,
    country_code,
    count() as total_requests,
    sum(is_blocked) as blocked_count,
    avg(response_time_ms) as avg_latency,
    quantile(0.99)(response_time_ms) as p99_latency
FROM security_events
GROUP BY ts_hour, threat_type, country_code;

-- Таблица для быстрых запросов (SummingMergeTree)
CREATE TABLE hourly_stats_agg (
    ts_hour DateTime,
    threat_type LowCardinality(String),
    country_code LowCardinality(String),
    total_requests UInt64,
    blocked_count UInt64,
    avg_latency Float32,
    p99_latency UInt32
) ENGINE = SummingMergeTree()
ORDER BY (ts_hour, threat_type, country_code);
```

**Преимущества подхода:**
-  **Сжатие:** 10-20× лучше Elasticsearch для лог-данных
-  **Партиционирование:** Быстрое удаление старых данных через TTL
-  **OLAP:** Мгновенные агрегации для дашбордов
-  **Масштабирование:** Добавление шардов без downtime

---