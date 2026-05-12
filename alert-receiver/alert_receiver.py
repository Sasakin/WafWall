import os
import sys
import json
import time
import logging
import argparse
import threading
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

alerts_cache = []
cache_lock = threading.Lock()


class StaticHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/alerts' or self.path == '/alerts.json':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            with cache_lock:
                self.wfile.write(json.dumps(alerts_cache, default=str).encode())
        elif self.path == '/' or self.path == '/index.html' or self.path == '/ui':
            self.path = '/alert-ui.html'
            super().do_GET()
        else:
            super().do_GET()

    def log_message(self, format, *args):
        pass


def run_http_server(port):
    server = HTTPServer(('', port), StaticHandler)
    logger.info(f"HTTP server running on port {port}")
    server.serve_forever()


def format_alert(alert: dict, severity: str) -> str:
    timestamp = alert.get("timestamp", datetime.utcnow().isoformat())
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass

    return (
        f"{'=' * 50}\n"
        f"[{severity}] ALERT @ {timestamp}\n"
        f"{'=' * 50}\n"
        f"ID:        {alert.get('alertId', 'N/A')}\n"
        f"Source IP: {alert.get('sourceIp', 'N/A')}\n"
        f"Threat:    {alert.get('threatType', 'N/A')}\n"
        f"Message:   {alert.get('message', 'N/A')}\n"
        f"Threshold: {alert.get('thresholdExceeded', 'N/A')} req/min\n"
        f"{'-' * 50}\n"
    )


def determine_severity(alert: dict) -> str:
    threat = str(alert.get("threatType", "")).upper()
    threshold = alert.get("thresholdExceeded", 0) or 0

    if threat == "DDOS_PATTERN" or threshold > 500:
        return "CRITICAL"
    elif threat in ("SQL_INJECTION", "XSS_ATTACK") or threshold > 100:
        return "HIGH"
    elif threat == "RATE_LIMIT_EXCEEDED" or threshold > 50:
        return "MEDIUM"
    return "LOW"


def log_to_file(alert: dict):
    log_dir = "/app/logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "alerts.log")
    with open(log_file, "a") as f:
        f.write(json.dumps(alert, default=str) + "\n")


def main():
    parser = argparse.ArgumentParser(description="WAF Alert Receiver with Web UI")
    parser.add_argument(
        "--ws-host",
        default=os.environ.get("WAF_ALERT_HOST", "alert"),
        help="WebSocket host (default: alert)",
    )
    parser.add_argument(
        "--ws-port",
        type=int,
        default=int(os.environ.get("WAF_ALERT_PORT", "8083")),
        help="WebSocket port (default: 8083)",
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=5000,
        help="UI HTTP port (default: 5000)",
    )
    args = parser.parse_args()

    http_thread = threading.Thread(target=run_http_server, args=(args.ui_port,), daemon=True)
    http_thread.start()

    try:
        import websocket
        import shutil

        ui_dir = os.path.dirname(os.path.abspath(__file__))
        static_dir = "/app/static"
        os.makedirs(static_dir, exist_ok=True)
        shutil.copy(os.path.join(ui_dir, "alert-ui.html"), os.path.join(static_dir, "alert-ui.html"))

    except ImportError:
        logger.warning("shutil not available, UI fallback may not work")

    ws_url = f"ws://{args.ws_host}:{args.ws_port}/ws"
    logger.info(f"Connecting via WebSocket to {ws_url}...")
    logger.info(f"UI available at http://localhost:{args.ui_port}")

    try:
        import websocket

        alerts_seen = set()

        def on_open(ws):
            logger.info("WebSocket connected, sending STOMP CONNECT...")
            ws.send("CONNECT\naccept-version:1.2\nhost:/\n\n\x00")

        def on_message(ws, message):
            frame = message.strip('\x00')

            if frame.startswith("CONNECTED"):
                logger.info("STOMP CONNECTED, subscribing to /topic/alerts...")
                ws.send("SUBSCRIBE\nid:sub-1\ndestination:/topic/alerts\n\n\x00")
                logger.info("Subscribed. Waiting for alerts...")
            elif frame.startswith("MESSAGE"):
                try:
                    body_start = frame.index("\n\n") + 2
                    body = frame[body_start:]
                    data = json.loads(body)
                    if isinstance(data, dict):
                        alert_id = data.get("alertId", str(data))
                        if alert_id not in alerts_seen:
                            alerts_seen.add(alert_id)
                            severity = determine_severity(data)
                            print(format_alert(data, severity))
                            log_to_file(data)
                            with cache_lock:
                                alerts_cache.insert(0, data)
                                if len(alerts_cache) > 100:
                                    alerts_cache.pop()
                except (json.JSONDecodeError, ValueError) as e:
                    logger.debug(f"Non-JSON frame: {e}")
            elif frame.startswith("ERROR"):
                logger.error(f"STOMP ERROR: {frame}")

        def on_error(ws, error):
            logger.error(f"WebSocket error: {error}")

        def on_close(ws, code, reason):
            logger.warning(f"WebSocket closed: {code} {reason}")

        ws = websocket.WebSocketApp(
            ws_url,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )

        logger.info("Starting WebSocket connection...")
        ws.run_forever(ping_interval=30, ping_timeout=10)

    except ImportError:
        logger.error("websocket-client library not found. Install: pip install websocket-client")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
