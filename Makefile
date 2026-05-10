.PHONY: help build up down restart logs demo clean

help:
	@echo "WAF Highload System - Make commands"
	@echo ""
	@echo "  make build    - Собрать все Java сервисы"
	@echo "  make up      - Запустить все сервисы (docker-compose)"
	@echo "  make down    - Остановить все сервисы"
	@echo "  make restart - Перезапустить все сервисы"
	@echo "  make logs    - Показать логи"
	@echo "  make demo    - Запустить resilience demo"
	@echo "  make clean   - Удалить Docker volumes"
	@echo ""

build:
	@echo "Building Java services..."
	./gradlew :common:build :gateway:build :processor:build :alert:build --no-daemon

up:
	@echo "Starting all services..."
	docker compose up -d
	@echo ""
	@echo "Services started:"
	@echo "  - WAF Gateway:    http://localhost:8080"
	@echo "  - Stream Processor: http://localhost:8081"
	@echo "  - Alert Service:  http://localhost:8083"
	@echo "  - Prometheus:     http://localhost:9090"
	@echo "  - Grafana:        http://localhost:3000 (admin/admin)"
	@echo "  - Kafka UI:       http://localhost:8085"
	@echo "  - Backend:        http://localhost:8090"

down:
	docker compose down

restart: down up

logs:
	docker compose logs -f

demo:
	@echo "Running resilience demo..."
	python demo/load_and_fail_demo.py

clean:
	docker compose down -v
	@echo "Docker volumes removed"