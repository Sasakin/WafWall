# План развития WAF + Analytics Pipeline + BotDetector

Основан на документах: `design.md` и `QWEN.md`

---

## Статус реализации

### ✅ Готово

| Компонент | Описание | Статус |
|----------|----------|--------|
| Docker Compose | Redis, Kafka, ClickHouse, Kafka UI | ✅ |
| ClickHouse Schema | Таблицы security_events, alerts, ip_blocklist | ✅ |
| WAF Gateway | Базовые SQLi, XSS фильтры | ✅ |
| Rate Limiting | Sliding window через Redis | ✅ |
| Proxy Service | Проксирование к бэкенду | ✅ |
| Prometheus Метрики | Counters, Timers, Gauges | ✅ |
| Health Checks | Проверка Redis, Kafka | ✅ |
| Bot Detection | Поведенческий анализ, UA, frequency, JS challenge | ✅ |
| Circuit Breaker | Closed/Open/Half-open states, Redis persistence | ✅ |
| Whitelist Service | IP whitelist с in-memory fallback | ✅ |
| Stream Processor | Kafka consumer, ClickHouse, GeoIP, Aggregation | ✅ |
| Anomaly Detection | DDoS, Brute-force detection | ✅ |
| Alert Service | WebSocket + Dashboard UI | ✅ |
| Blocklist Service | IP blocklist management | ✅ |

---

## План развития (12 недель)

### Фаза 1: Базовая функциональность ✅

#### Неделя 1: Инфраструктура
- [x] Docker Compose для локальной разработки
- [x] SQL-скрипты для ClickHouse
- [x] Настройка Redis, Kafka, ClickHouse
- [x] Интеграционные тесты (tests/)

#### Неделя 2: WAF Gateway
- [x] Базовые SQL-инъекции паттерны
- [x] Базовый XSS фильтр
- [x] Проксирование к бэкенду

#### Неделя 3: Redis интеграция
- [x] Rate limiting с Redis
- [x] IP reputation (интегрирован в BotDetection)
- [x] Fallback при недоступности Redis

---

### Фаза 2: Расширенная защита ✅

#### Неделя 4: Bot Detection
- [x] **Цель**: Детектирование ботов по поведенческим паттернам
- [x] Расширить поведенческий анализ
- [x] JS cookie (JavaScript challenge) проверка
- [x] Frequency analysis (50+ запросов/мин = бот)
- [x] User-Agent анализ (пустые, известные боты)
- [x] Navigation patterns (Referrer, Direct access)
- [ ] Интеграция с ML моделями *(опционально)*

#### Неделя 5: Whitelist и Fallback
- [x] **Цель**: Graceful degradation при сбоях
- [x] Whitelist IP/эндпоинтов
- [x] Локальный in-memory rate limiting
- [ ] Retry логика для Kafka
- [ ] Буферизация событий локально

#### Неделя 6: Circuit Breaker
- [x] **Цель**: Отказоустойчивость
- [x] Circuit breaker для Redis
- [x] Circuit breaker для Kafka
- [x] Fallback стратегии

---

### Фаза 3: Stream Processor ✅

#### Неделя 7: Потоковая аналитика
- [x] **Цель**: Агрегация и обогащение событий
- [x] Агрегация событий (окно 1 минута)
- [x] GeoIP обогащение
- [x] ClickHouse batch inserts
- [x] Materialized views для дашбордов (5 шт)

#### Неделя 8: Anomaly Detection
- [x] **Цель**: Автоматическое детектирование атак
- [x] DDoS Detection (>50 блокировок/мин)
- [x] Brute-force Detection (>10 попыток на эндпоинт)
- [x] Отправка алертов в security.alerts topic

---

### Фаза 4: Alert Service ✅

#### Неделя 9: Уведомления
- [x] **Цель**: Real-time уведомления
- [x] WebSocket push + HTML Dashboard (вместо Telegram Bot)
- [ ] Email уведомления *(опционально)*
- [ ] Slack интеграция *(опционально)*

#### Неделя 10: Управление блокировками
- [x] **Цель**: Автоматическая блокировка
- [x] IP Blocklist в Redis
- [x] TTL для блокировок
- [x] Manual block/unblock API

---

### Фаза 5: Мониторинг и оптимизация

#### Неделя 11: Grafana и дашборды
- [x] **Цель**: Визуализация
- [x] Grafana дашборд - Общий трафик (01-traffic-dashboard.json)
- [x] Grafana дашборд - Угрозы по типам (02-threats-dashboard.json)
- [x] Grafana дашборд - Топ блокированных IP (03-top-blocked-ips-dashboard.json)
- [x] Grafana дашборд - Latency (p50, p95, p99) (04-latency-dashboard.json)
- [ ] Alert rules в Prometheus

#### Неделя 12: Нагрузочное тестирование
- [x] **Цель**: Проверка требований
- [x] JMeter скрипты (4 теста в jmeter/)
- [x] Docker Compose с gateway, processor, alert
- [x] Resilience demo скрипт (demo/load_and_fail_demo.py)
- [ ] Тест 100k+ RPS *(запустить локально)*
- [ ] Оптимизация индексов ClickHouse
- [ ] Тюнинг JVM параметров

---

## Приоритизация

### ✅ Реализовано (P0-P1)

| Компонент | Описание |
|-----------|----------|
| Bot Detection | Поведенческий анализ, UA, frequency, JS challenge |
| Circuit Breaker | Closed/Open/Half-open, Redis persistence |
| DDoS Detection | >50 блокировок/мин |
| WebSocket + Dashboard UI | Real-time уведомления |
| Whitelist сервис | IP whitelist |
| Rate Limiting | Sliding window |
| Stream Processor | Kafka → ClickHouse + GeoIP |
| Blocklist | IP management с TTL |

### P1 - Важно

| Компонент | Описание |
|-----------|----------|
| Grafana дашборды | 4 дашборда ✅ |

### P2 - Полезно

| Компонент | Описание |
|-----------|----------|
| Нагрузочное тестирование | JMeter 100k+ RPS |
| Materialized views | ClickHouse оптимизация |
| ML классификация | Machine Learning |
| Email/Slack интеграция | Доп. уведомления |

---

## Технические требования (из design.md)

| Требование | Значение |
|------------|---------|
| Пропускная способность | 100,000+ RPS |
| Задержка фильтрации | < 5ms (p99) |
| Доступность | 99.9% |
| Время детектирования | < 1 секунды |
| Хранение аналитики | 30+ дней |

---

## Следующие шаги

Для highload демо **основные компоненты уже реализованы**:

### Приоритеты для завершения:

| Приоритет | Компонент | Описание |
|-----------|-----------|----------|
| P2 | Тест 100k+ RPS | Запустить локально с JMeter |
| P2 | Email/Slack уведомления | Опционально |

### Запуск системы:
```bash
make build    # Собрать JAR файлы
make up       # Запустить docker-compose
make demo     # Запустить resilience demo
```