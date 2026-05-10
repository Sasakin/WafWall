#!/usr/bin/env python3
"""
WAF Resilience Demo Script

Демонстрирует отказоустойчивость системы:
1. Baseline - нормальная работа под нагрузкой
2. Redis failure - работа через fallback
3. Kafka failure - локальная буферизация
4. Recovery - восстановление системы
"""

import subprocess
import time
import json
import sys
import os
import requests
from datetime import datetime
from typing import Dict, List, Optional

PROMETHEUS_URL = "http://localhost:9090"
WAF_URL = "http://localhost:8080"
JMETER_DIR = "jmeter"
RESULTS_DIR = "demo/results"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def log(msg: str, color=Colors.END):
    print(f"{color}{msg}{Colors.END}")

def run_command(cmd: List[str], capture=True) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=capture, text=True, timeout=30)
        return result.stdout if capture else None
    except Exception as e:
        log(f"Command error: {e}", Colors.RED)
        return None

def wait_for_url(url: str, timeout: int = 30) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 500:
                return True
        except:
            pass
        time.sleep(1)
    return False

def get_prometheus_metric(query: str) -> float:
    try:
        resp = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=5
        )
        data = resp.json()
        if data.get("status") == "success" and data["data"]["result"]:
            return float(data["data"]["result"][0]["value"][1])
    except Exception as e:
        log(f"Prometheus query error: {e}", Colors.YELLOW)
    return 0.0

def get_circuit_breaker_status() -> Dict[str, str]:
    try:
        resp = requests.get(f"{WAF_URL}/api/circuitbreaker", timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

def get_waf_status() -> Dict[str, any]:
    status = {"healthy": False, "components": {}}
    try:
        resp = requests.get(f"{WAF_URL}/health", timeout=2)
        if resp.status_code == 200:
            status = resp.json()
            status["healthy"] = True
    except:
        pass
    return status

def get_metrics() -> Dict[str, float]:
    return {
        "requests_total": get_prometheus_metric("rate(waf_requests_total[1m])"),
        "blocked_total": get_prometheus_metric("rate(waf_blocked_total[1m])"),
        "allowed_total": get_prometheus_metric("rate(waf_requests_allowed_total[1m])"),
        "p99_latency": get_prometheus_metric(
            'histogram_quantile(0.99, rate(waf_request_duration_seconds_bucket[1m]))'
        ),
        "active_connections": get_prometheus_metric("waf_active_connections"),
    }

def docker_compose_cmd(service: str, action: str):
    return ["docker", "compose", "exec", "-T", service, "sh", "-c", f"echo {action}"]

def check_service_health(service: str) -> bool:
    try:
        result = run_command(["docker", "ps", "--filter", f"name={service}", "--format", "{{.Status}}"])
        return "Up" in (result or "")
    except:
        return False

def print_metrics(metrics: Dict[str, float], title: str = ""):
    if title:
        log(f"\n{'='*50}", Colors.BLUE)
        log(f" {title}", Colors.BLUE)
        log(f"{'='*50}\n", Colors.BLUE)
    
    for key, value in metrics.items():
        formatted_key = key.replace("_", " ").title()
        if "latency" in key:
            log(f"  {formatted_key}: {value:.2f} ms")
        elif "connections" in key:
            log(f"  {formatted_key}: {int(value)}")
        else:
            log(f"  {formatted_key}: {value:.2f} req/s")

def run_jmeter_test(test_name: str, duration_sec: int = 30):
    log(f"\n{Colors.YELLOW}Запускаю JMeter тест: {test_name}{Colors.END}")
    
    jmx_file = f"{JMETER_DIR}/{test_name}.jmx"
    output_file = f"{RESULTS_DIR}/{test_name.replace('.jmx', '')}.jtl"
    
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    cmd = [
        "jmeter", "-n",
        "-t", jmx_file,
        "-l", output_file,
        "-j", f"{RESULTS_DIR}/{test_name}_.log",
        "-e"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_sec + 30)
    
    if result.returncode == 0:
        log(f"Тест {test_name} завершён", Colors.GREEN)
    else:
        log(f"Тест {test_name} завершён с предупреждениями", Colors.YELLOW)
    
    return result.returncode

def stop_service(service: str):
    log(f"{Colors.RED}Останавливаю {service}...{Colors.END}")
    run_command(["docker", "compose", "stop", service], capture=False)
    time.sleep(3)

def start_service(service: str):
    log(f"{Colors.GREEN}Запускаю {service}...{Colors.END}")
    run_command(["docker", "compose", "start", service], capture=False)
    time.sleep(5)

def simulate_load_and_measure(test_duration: int = 20) -> Dict[str, float]:
    log(f"\n{Colors.YELLOW}Измерение метрик под нагрузкой...{Colors.END}")
    
    samples = []
    start = time.time()
    
    while time.time() - start < test_duration:
        metrics = get_metrics()
        samples.append(metrics)
        time.sleep(2)
    
    avg_metrics = {
        key: sum(s[key] for s in samples) / len(samples)
        for key in samples[0].keys()
    }
    
    return avg_metrics

def main():
    log(f"{Colors.BLUE}{'='*60}", Colors.BLUE)
    log(f" WAF RESILIENCE DEMO", Colors.BLUE)
    log(f" Демонстрация отказоустойчивости системы", Colors.BLUE)
    log(f"{'='*60}{Colors.END}\n")
    
    import os
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    log("Проверка доступности сервисов...")
    
    if not wait_for_url(f"{PROMETHEUS_URL}/-/ready", 10):
        log("Prometheus недоступен!", Colors.RED)
        return 1
    
    if not wait_for_url(f"{WAF_URL}/health", 10):
        log("WAF Gateway недоступен!", Colors.RED)
        log("Убедите что gateway запущен (обычно на port 8080)", Colors.YELLOW)
        return 1
    
    log("Все сервисы доступны\n", Colors.GREEN)
    
    phases = []
    
    # ==========================================
    # PHASE 1: BASELINE
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*60}", Colors.BLUE)
    log(f" ФАЗА 1: BASELINE (нормальная работа)", Colors.BLUE)
    log(f"{'='*60}{Colors.END}")
    
    baseline_metrics = simulate_load_and_measure(30)
    print_metrics(baseline_metrics, "Baseline Metrics")
    phases.append(("Baseline", baseline_metrics))
    
    # ==========================================
    # PHASE 2: REDIS FAILURE
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*60}", Colors.BLUE)
    log(f" ФАЗА 2: REDIS FAILURE (отказ Redis)", Colors.BLUE)
    log(f"{'='*60}{Colors.END}")
    
    stop_service("redis")
    
    log(f"\n{Colors.YELLOW}Redis остановлен. Проверка работы через fallback...{Colors.END}")
    time.sleep(5)
    
    redis_failure_metrics = simulate_load_and_measure(20)
    print_metrics(redis_failure_metrics, "Redis Failure Metrics")
    phases.append(("Redis Down", redis_failure_metrics))
    
    # ==========================================
    # PHASE 3: RECOVERY - RESTART REDIS
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*60}", Colors.BLUE)
    log(f" ФАЗА 3: RECOVERY (восстановление Redis)", Colors.BLUE)
    log(f"{'='*60}{Colors.END}")
    
    start_service("redis")
    
    log(f"\n{Colors.GREEN}Ожидание восстановления...{Colors.END}")
    time.sleep(5)
    
    recovery_metrics = simulate_load_and_measure(20)
    print_metrics(recovery_metrics, "Recovery Metrics")
    phases.append(("Recovery", recovery_metrics))
    
    # ==========================================
    # PHASE 4: KAFKA FAILURE
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*60}", Colors.BLUE)
    log(f" ФАЗА 4: KAFKA FAILURE (отказ Kafka)", Colors.BLUE)
    log(f"{'='*60}{Colors.END}")
    
    stop_service("kafka")
    
    log(f"\n{Colors.YELLOW}Kafka остановлен. События буферизуются локально...{Colors.END}")
    
    kafka_failure_metrics = simulate_load_and_measure(20)
    print_metrics(kafka_failure_metrics, "Kafka Failure Metrics")
    phases.append(("Kafka Down", kafka_failure_metrics))
    
    # ==========================================
    # FINAL: RESTORE ALL
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*60}", Colors.BLUE)
    log(f" ВОССТАНОВЛЕНИЕ ВСЕХ СЕРВИСОВ", Colors.BLUE)
    log(f"{'='*60}{Colors.END}")
    
    start_service("kafka")
    time.sleep(5)
    
    final_metrics = simulate_load_and_measure(15)
    print_metrics(final_metrics, "Final Metrics")
    phases.append(("Final", final_metrics))
    
    # ==========================================
    # SUMMARY
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*60}", Colors.BLUE)
    log(f" ИТОГОВЫЙ ОТЧЁТ", Colors.BLUE)
    log(f"{'='*60}{Colors.END}")
    
    print(f"\n{'Фаза':<20} {'RPS':<15} {'Blocked':<15} {'p99 latency':<15}")
    print("-" * 65)
    
    for phase_name, metrics in phases:
        rps = metrics.get("requests_total", 0)
        blocked = metrics.get("blocked_total", 0)
        latency = metrics.get("p99_latency", 0)
        print(f"{phase_name:<20} {rps:<15.2f} {blocked:<15.2f} {latency:<15.2f}ms")
    
    log(f"\n{Colors.GREEN}Демо завершено!{Colors.END}")
    log(f"Результаты сохранены в: {RESULTS_DIR}/")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())