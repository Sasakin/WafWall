# WAF Redis Resilience Test

Тест демонстрирует отказоустойчивость WAF системы при отказе Redis.

## Что тестируется

1. **Baseline** - система работает нормально с Redis
2. **Redis Failure** - Redis останавливается, система переходит в fallback mode
3. **Recovery** - Redis восстанавливается, система возвращается в норму

## Запуск

### 1. Запустить инфраструктуру

```bash
docker compose up -d
```

Подождать 30 секунд для инициализации.

### 2. Запустить JMeter

Убедитесь, что JMeter установлен и доступен в PATH (или `jmeter.bat` для Windows).

### 3. Запустить тест

```bash
python demo/load_and_fail_demo.py
```

## Ожидаемый результат

```
PHASE 1: BASELINE - работа с Redis
- RPS: ~50-100 req/s
- Blocked: > 0 (WAF блокирует атаки)
- Allowed: > 0 (валидные запросы проходят)

PHASE 2: REDIS FAILURE - fallback mode
- RPS: продолжается (система не упала)
- Blocked: 0 (fallback отключает блокировки)
- Allowed: продолжается (система пропускает весь трафик)

PHASE 3: RECOVERY
- RPS: восстанавливается
- Blocked: > 0
- Allowed: > 0
```

## Результаты

Отчеты JMeter сохраняются в:
- `demo/results/02-waf-blocking-test.jtl` - данные теста
- `demo/results/02-waf-blocking-test-html/` - HTML отчет

## Требования

- Python 3.x
- Docker + Docker Compose
- JMeter 5.x
- requests library (`pip install requests`)
