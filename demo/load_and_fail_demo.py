#!/usr/bin/env python3
"""
WAF Redis Resilience Test

Тестирует:
1. Запуск jmeter теста 02-waf-blocking-test.jmx
2. Отказ Redis - система продолжает работать (fallback)
3. Восстановление Redis - система возвращается в норму
"""

import subprocess
import time
import os
import sys
import threading
import queue
from typing import Dict

PROMETHEUS_URL = "http://localhost:9090"
WAF_URL = "http://localhost:8080"
DEMO_DIR = "demo"
JMETER_TEST = "02-waf-blocking-test.jmx"


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
    try:
        r = requests.get(f"{WAF_URL}/api/test", timeout=2)
        return r.status_code
    except:
        return 0


def monitor_loop(stop_event, results_queue):
    while not stop_event.is_set():
        metrics = get_all_metrics()
        waf_status = send_test_request()
        metrics["waf_status"] = waf_status
        results_queue.put(metrics)
        time.sleep(2)


def run_jmeter(test_file: str, duration: int = 60):
    os.makedirs(f"{DEMO_DIR}/results", exist_ok=True)
    jmeter_cmd = "jmeter.bat" if os.name == "nt" else "jmeter"
    result_file = f"{DEMO_DIR}/results/{test_file.replace('.jmx','.jtl')}"
    html_folder = f"{DEMO_DIR}/results/{test_file.replace('.jmx','-html')}"
    cmd = [
        jmeter_cmd, "-n",
        "-t", f"jmeter/{test_file}",
        "-l", result_file,
        "-j", f"{DEMO_DIR}/results/jmeter.log",
        "-e", "-o", html_folder
    ]
    log(f"Запуск JMeter: {test_file}")
    result = run_cmd(cmd, timeout=duration + 30)
    return result, result_file, html_folder


def stop_redis():
    log(f"{Colors.RED}>>> ОСТАНОВКА REDIS <<<{Colors.RED}")
    run_cmd(["docker", "compose", "stop", "redis"], capture=False)
    time.sleep(2)


def start_redis():
    log(f"{Colors.GREEN}>>> ЗАПУСК REDIS <<<{Colors.GREEN}")
    run_cmd(["docker", "compose", "start", "redis"], capture=False)
    time.sleep(5)


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


def check_redis_alive() -> bool:
    try:
        r = requests.get(f"{WAF_URL}/health", timeout=3)
        return r.status_code < 500
    except:
        return False


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
    log(" WAF REDIS RESILIENCE TEST", Colors.CYAN)
    log(f"{'='*70}{Colors.END}\n")

    phases = []

    log("Проверка Prometheus...")
    if not wait_for_service(f"{PROMETHEUS_URL}/-/ready", "Prometheus"):
        log("Prometheus недоступен. Запустите: docker compose up -d", Colors.RED)
        return 1

    log("Проверка WAF...")
    if not wait_for_service(f"{WAF_URL}/health", "WAF"):
        log("WAF недоступен. Запустите: docker compose up -d", Colors.RED)
        return 1

    log("Сервисы готовы\n", Colors.GREEN)

    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" PHASE 1: BASELINE - работа с Redis", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")

    stop_event = threading.Event()
    results_queue = queue.Queue()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event, results_queue))
    monitor_thread.start()

    run_jmeter(JMETER_TEST, duration=30)

    samples = []
    while not results_queue.empty():
        samples.append(results_queue.get())
    stop_event.set()
    monitor_thread.join()

    print_results(samples, "BASELINE (Redis OK)")
    phases.append(("Baseline", samples))

    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" PHASE 2: REDIS FAILURE - fallback mode", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")

    stop_event = threading.Event()
    results_queue = queue.Queue()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event, results_queue))
    monitor_thread.start()

    stop_redis()
    time.sleep(20)

    samples = []
    while not results_queue.empty():
        samples.append(results_queue.get())
    stop_event.set()
    monitor_thread.join()

    print_results(samples, "REDIS FAILURE (fallback)")
    phases.append(("Redis Down", samples))

    log(f"\n{Colors.BLUE}{'='*70}", Colors.BLUE)
    log(" PHASE 3: RECOVERY - Redis restored", Colors.BLUE)
    log(f"{'='*70}{Colors.END}")

    start_redis()
    wait_for_service(f"{WAF_URL}/health", "WAF + Redis", 30)

    stop_event = threading.Event()
    results_queue = queue.Queue()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event, results_queue))
    monitor_thread.start()

    time.sleep(20)

    samples = []
    while not results_queue.empty():
        samples.append(results_queue.get())
    stop_event.set()
    monitor_thread.join()

    print_results(samples, "RECOVERY")
    phases.append(("Recovery", samples))

    log(f"\n{Colors.CYAN}{'='*70}", Colors.CYAN)
    log(" FINAL REPORT", Colors.CYAN)
    log(f"{'='*70}{Colors.END}\n")

    print(f"{'Phase':<20} {'RPS':>10} {'p99 ms':>10} {'WAF OK':>10}")
    print("-" * 55)

    for name, samples in phases:
        if samples:
            avg = sum(s.get('rps', 0) for s in samples) / len(samples)
            p99 = sum(s.get('p99', 0) for s in samples) / len(samples)
            ok = sum(1 for s in samples if s.get('waf_status', 0) in [200, 403, 404])
            pct = 100 * ok / len(samples)
            status = f"{ok}/{len(samples)} ({pct:.0f}%)"
            print(f"{name:<20} {avg:>10.1f} {p99:>10.1f} {status:>10}")

    log(f"\n{Colors.GREEN}Test completed!{Colors.END}")
    log(f"Results: {DEMO_DIR}/results/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
