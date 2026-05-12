# JMeter Load Tests for WAF Gateway

## Требования

- JMeter 5.5+ (скачать с https://jmeter.apache.org/)
- Java 11+

## Тесты

| Файл | Описание | Цель |
|------|----------|------|
| `01-basic-load-test.jmx` | Базовый load test | 25k RPS |
| `02-waf-blocking-test.jmx` | Тест блокировки SQLi/XSS | Проверка WAF |
| `03-stress-test.jmx` | Stress test (10k→25k→50k) | Найти точку отказа |
| `04-spike-test.jmx` | Spike test (10k→50k→10k) | Проверка resilience |

## Запуск

### GUI режим
```bash
./jmeter.sh          # Linux/Mac
jmeter.bat           # Windows
```

Открыть `.jmx` файл в GUI и нажать Run.

### CLI режим (рекомендуется для нагрузки)
```bash
# очистить данные перед тестом
docker exec waf-redis redis-cli FLUSHALL 
docker exec waf-clickhouse clickhouse-client -q "TRUNCATE TABLE security.waf_logs" 

# Basic load test - 100k RPS
jmeter -n -t 01-basic-load-test.jmx -l results/load.jtl -e -o results/load-report

# WAF blocking test
jmeter -n -t 02-waf-blocking-test.jmx -l results/blocking.jtl -e -o results/basic-report
```

## Конфигурация

Редактировать переменные в тестах:
- `WAF_HOST` - адрес WAF Gateway (по умолчанию localhost)
- `WAF_PORT` - порт WAF Gateway (по умолчанию 8080)

## Ожидаемые результаты

### 01-basic-load-test (25k RPS)
- RPS: ~25,000
- Error rate: < 1%
- p99 latency: 15-25ms (single machine)

### 04-spike-test
- Spike до 50k: система должна восстановиться
- Recovery time: < 30 сек

## Мониторинг

Добавить в Grafana:
- JMeter results → InfluxDB
- Или использовать HTML отчёт (`-e -o results/report`)

## Структура результатов

```
jmeter/
├── results/
│   ├── basic.jtl
│   ├── blocking.jtl
│   ├── stress.jtl
│   └── spike.jtl
└── reports/          # HTML отчёты
```