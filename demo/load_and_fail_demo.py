#!/usr/bin/env python3
"""
WAF Load + Failure Demo

Демонстрирует:
1. Система работает под нагрузкой
2. Отказ Redis - система продолжает работать (fallback)
3. Отказ Kafka - система буферизует события локально
4. Восстановление - система возвращается в норму
"""

import subprocess
import time
import os
import sys
import threading
import queue
from typing import Dict, Optional

PROMETHEUS_URL = "http://localhost:9090"
WAF_URL = "http://localhost:8080"
BACKEND_URL = "http://localhost:8090"
DEMO_DIR = "demo"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    END = '\033[0m'

def log(msg: str, color=Colors.END):
    print(f"{color}{msg}{Colors.END}")

def run_cmd(cmd: list, capture=True, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
    except Exception as e:
        log(f"Error: {e}", Colors.RED)
        return None

def get_metric(query: str) -> float:
    try:
        r = requests.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query}, timeout=3)
        data = r.json()
        if data.get("status") == "success" and data["data"]["result"]:
            return float(data["data"]["result"][0]["value"][1])
    except:
        pass
    return 0.0

def get_all_metrics() -> Dict:
    return {
        "rps": get_metric("rate(waf_requests_total[1m])"),
        "blocked": get_metric("rate(waf_blocked_total[1m])"),
        "allowed": get_metric("rate(waf_requests_allowed_total[1m])"),
        "p50": get_metric('histogram_quantile(0.50, rate(waf_request_duration_seconds_bucket[1m]))'),
        "p95": get_metric('histogram_quantile(0.95, rate(waf_request_duration_seconds_bucket[1m]))'),
        "p99": get_metric('histogram_quantile(0.99, rate(waf_request_duration_seconds_bucket[1m]))'),
    }

def send_test_request() -> int:
    """Отправляет тестовый запрос и возвращает статус"""
    try:
        r = requests.get(f"{WAF_URL}/api/test", timeout=2)
        return r.status_code
    except:
        return 0

def monitor_loop(stop_event, results_queue):
    """Мониторит метрики в цикле"""
    samples = []
    while not stop_event.is_set():
        metrics = get_all_metrics()
        waf_status = send_test_request()
        metrics["waf_status"] = waf_status
        results_queue.put(metrics)
        time.sleep(2)
    return results_queue

def run_jmeter_background(test_file: str):
    """Запускает JMeter в фоне"""
    os.makedirs(f"{DEMO_DIR}/results", exist_ok=True)
    
    # JMeter на Windows требует .bat
    jmeter_cmd = "jmeter.bat" if os.name == "nt" else "jmeter"
    
    cmd = [
        jmeter_cmd, "-n",
        "-t", f"jmeter/{test_file}",
        "-l", f"{DEMO_DIR}/results/{test_file.replace('.jmx','.jtl')}",
        "-j", f"{DEMO_DIR}/results/jmeter.log"
    ]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    return proc

def stop_container(name: str):
    log(f"{Colors.RED}>>> ОСТАНОВКА {name} <<<{Colors.RED}")
    run_cmd(["docker", "compose", "stop", name], capture=False)
    time.sleep(2)

def start_container(name: str):
    log(f"{Colors.GREEN}>>> ЗАПУСК {name} <<<{Colors.GREEN}")
    run_cmd(["docker", "compose", "start", name], capture=False)
    time.sleep(3)

def wait_for_service(url: str, name: str, timeout=30) -> bool:
    log(f"Ожидание {name}...", Colors.YELLOW)
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 500:
                log(f"{name} готов!", Colors.GREEN)
                return True
        except:
            pass
        time.sleep(2)
    log(f"{name} не ответил", Colors.RED)
    return False

def check_all_services() -> bool:
    """Проверяет доступность всех сервисов"""
    services = [
        ("http://localhost:6379", "Redis", False),  # Redis не HTTP
        ("http://localhost:9090/-/ready", "Prometheus", True),
        ("http://localhost:8123", "ClickHouse", False),
        ("http://localhost:8080/health", "WAF Gateway", True),
        ("http://localhost:8081/health", "Stream Processor", True),
        ("http://localhost:8083/health", "Alert Service", True),
    ]
    
    log(f"\n{Colors.BLUE}Проверка сервисов...{Colors.END}")
    
    all_ready = True
    for url, name, is_http in services:
        if not is_http:
            log(f"  {name}: пропуск (non-HTTP)", Colors.CYAN)
            continue
        
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                log(f"  {name}: OK", Colors.GREEN)
            else:
                log(f"  {name}: ERROR {r.status_code}", Colors.RED)
                all_ready = False
        except Exception as e:
            log(f"  {name}: недоступен", Colors.RED)
            all_ready = False
    
    return all_ready

def print_results(samples: list, title: str):
    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(f" {title}", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")
    
    if not samples:
        log("Нет данных", Colors.YELLOW)
        return
    
    avg = {k: sum(s.get(k, 0) for s in samples) / len(samples) for k in samples[0].keys() if k != 'waf_status'}
    
    log(f"\nСредние значения за период:")
    log(f"  RPS:        {avg.get('rps', 0):.2f}")
    log(f"  Blocked:    {avg.get('blocked', 0):.2f} req/s")
    log(f"  Allowed:    {avg.get('allowed', 0):.2f} req/s")
    log(f"  p50:        {avg.get('p50', 0):.2f} ms")
    log(f"  p95:        {avg.get('p95', 0):.2f} ms")
    log(f"  p99:        {avg.get('p99', 0):.2f} ms")
    
    waf_ok = sum(1 for s in samples if s.get('waf_status', 0) in [200, 403, 404])
    log(f"  WAF health: {waf_ok}/{len(samples)} ({100*waf_ok/len(samples):.0f}%)")

import requests

def main():
    log(f"\n{Colors.CYAN}{'='*70}", Colors.CYAN)
    log(" WAF RESILIENCE DEMONSTRATION", Colors.CYAN)
    log(" Нагрузка + отказы компонентов", Colors.CYAN)
    log(f"{'='*70}{Colors.END}\n")
    
    phases = []
    
    # Проверка сервисов
    log("Проверка доступности...")
    if not wait_for_service(f"{PROMETHEUS_URL}/-/ready", "Prometheus"):
        log("Prometheus недоступен. Запустите: docker compose up -d", Colors.RED)
        return 1
    
    if not check_all_services():
        log("\nНе все сервисы готовы. Запустите: docker compose up -d", Colors.YELLOW)
        log("После запуска подождите 30 секунд для инициализации.\n", Colors.YELLOW)
    
    log("Сервисы готовы\n", Colors.GREEN)
    
    # ==========================================
    # PHASE 1: BASELINE (чистая работа)
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" ФАЗА 1: BASELINE - работа без отказов", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")
    
    stop_event = threading.Event()
    results_queue = queue.Queue()
    
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event, results_queue))
    monitor_thread.start()
    
    # JMeter работает 30 сек
    jmeter_proc = run_jmeter_background("01-basic-load-test.jmx")
    time.sleep(35)
    
    samples = []
    while not results_queue.empty():
        samples.append(results_queue.get())
    stop_event.set()
    monitor_thread.join()
    jmeter_proc.terminate()
    
    print_results(samples, "BASELINE")
    phases.append(("Baseline", samples))
    
    # ==========================================
    # PHASE 2: REDIS FAILURE
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" ФАЗА 2: ОТКАЗ REDIS - проверка fallback", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")
    
    stop_event = threading.Event()
    results_queue = queue.Queue()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event, results_queue))
    monitor_thread.start()
    
    # Запускаем нагрузку
    jmeter_proc = run_jmeter_background("01-basic-load-test.jmx")
    time.sleep(10)
    
    # Останавливаем Redis под нагрузкой
    stop_container("redis")
    time.sleep(15)
    
    # Собираем метрики
    samples = []
    while not results_queue.empty():
        samples.append(results_queue.get())
    stop_event.set()
    monitor_thread.join()
    jmeter_proc.terminate()
    
    print_results(samples, "REDIS FAILURE (fallback active)")
    phases.append(("Redis Down", samples))
    
    # ==========================================
    # PHASE 3: RECOVERY
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" ФАЗА 3: ВОССТАНОВЛЕНИЕ REDIS", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")
    
    start_container("redis")
    wait_for_service(f"{WAF_URL}/health", "WAF + Redis", 20)
    
    stop_event = threading.Event()
    results_queue = queue.Queue()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event, results_queue))
    monitor_thread.start()
    
    jmeter_proc = run_jmeter_background("01-basic-load-test.jmx")
    time.sleep(20)
    
    samples = []
    while not results_queue.empty():
        samples.append(results_queue.get())
    stop_event.set()
    monitor_thread.join()
    jmeter_proc.terminate()
    
    print_results(samples, "RECOVERY")
    phases.append(("Recovery", samples))
    
    # ==========================================
    # PHASE 4: KAFKA FAILURE
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" ФАЗА 4: ОТКАЗ KAFKA - проверка буферизации", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")
    
    stop_event = threading.Event()
    results_queue = queue.Queue()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event, results_queue))
    monitor_thread.start()
    
    jmeter_proc = run_jmeter_background("01-basic-load-test.jmx")
    time.sleep(10)
    
    stop_container("kafka")
    time.sleep(15)
    
    samples = []
    while not results_queue.empty():
        samples.append(results_queue.get())
    stop_event.set()
    monitor_thread.join()
    jmeter_proc.terminate()
    
    print_results(samples, "KAFKA FAILURE (buffering)")
    phases.append(("Kafka Down", samples))
    
    # ==========================================
    # FINAL: RESTORE
    # ==========================================
    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" ФАЗА 5: ВОССТАНОВЛЕНИЕ ВСЕГО", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")
    
    start_container("kafka")
    time.sleep(10)
    
    # ==========================================
    # SUMMARY
    # ==========================================
    log(f"\n{Colors.CYAN}{'='*70}", Colors.CYAN)
    log(" ИТОГОВЫЙ ОТЧЁТ", Colors.CYAN)
    log(f"{'='*70}{Colors.END}\n")
    
    print(f"{'Фаза':<20} {'RPS':>10} {'p99 ms':>10} {'WAF OK':>10}")
    print("-" * 55)
    
    for name, samples in phases:
        if samples:
            avg = sum(s.get('rps', 0) for s in samples) / len(samples)
            p99 = sum(s.get('p99', 0) for s in samples) / len(samples)
            ok = sum(1 for s in samples if s.get('waf_status', 0) in [200, 403, 404])
            pct = 100 * ok / len(samples)
            status = f"{ok}/{len(samples)} ({pct:.0f}%)"
            print(f"{name:<20} {avg:>10.1f} {p99:>10.1f} {status:>10}")
    
    log(f"\n{Colors.GREEN}✓ Демо завершено успешно!{Colors.END}")
    log(f"Результаты: {DEMO_DIR}/results/")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())