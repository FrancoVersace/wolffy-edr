from __future__ import annotations

import json
import logging
import platform
import queue
import signal
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from common import VERSION
from common.config import load_agent_config, resolve_path
from common.paths import DATA_DIR, ensure_dirs
from common.security import resolve_secret, sign

from .buffer import LocalBuffer
from .context import Context
from .file_monitor import FileMonitor
from .listening_port_monitor import ListeningPortMonitor
from .network_monitor import NetworkMonitor
from .process_monitor import ProcessMonitor
from .rules_engine import RulesEngine
from .system_monitor import SystemMonitor

log = logging.getLogger("wolffy.agent")

DROP_STATUS = {400, 413, 422}
AUTH_STATUS = {401, 403}


class Agent:
    def __init__(self, cfg=None):
        ensure_dirs()
        self.cfg = cfg or load_agent_config()
        server_cfg = self.cfg["server"]
        self.stop_event = threading.Event()
        self.ctx = Context(self.stop_event, DATA_DIR)
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()}"
        self.agent_id = self._load_agent_id()
        self.secret = resolve_secret(server_cfg.get("secret_key"))
        self.base_url = server_cfg["url"]
        self.engine = RulesEngine(
            resolve_path(self.cfg["agent"]["rules_file"]), self.cfg["allowlist"]
        )
        self.buffer = LocalBuffer(DATA_DIR / "agent_buffer.db", self.cfg["buffer"]["max_events"])
        self.queue = queue.Queue(maxsize=20000)
        self.forward = set(self.cfg["telemetry"]["forward"] or [])
        self.max_per_minute = int(self.cfg["telemetry"]["max_per_minute"])
        self.session = requests.Session()
        self.session.verify = server_cfg.get("ca_bundle") or bool(server_cfg.get("verify_tls", True))
        self.ip_address = self._detect_ip()
        self.dropped = 0
        self._connected = None
        self._last_contact = 0.0
        self._threads = []
        self._monitors = []

    def _load_agent_id(self):
        path = DATA_DIR / "agent_id"
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
        value = f"{self.hostname}-{uuid.uuid4().hex[:8]}"
        path.write_text(value, encoding="utf-8")
        return value

    def _detect_ip(self):
        parsed = urlparse(self.base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((host, port))
                return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def emit(self, event):
        event.setdefault("uid", uuid.uuid4().hex)
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat(timespec="milliseconds"))
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1

    def _envelope(self, events):
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "ip_address": self.ip_address,
            "version": VERSION,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "events": events,
        }

    def _post(self, path, payload):
        body = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
        timestamp = f"{time.time():.3f}"
        headers = {
            "Content-Type": "application/json",
            "X-Wolffy-Timestamp": timestamp,
            "X-Wolffy-Signature": sign(self.secret, timestamp, body),
        }
        return self.session.post(
            self.base_url + path, data=body, headers=headers,
            timeout=float(self.cfg["server"]["timeout"]),
        )

    def _set_connected(self, state, detail=""):
        if state != self._connected:
            self._connected = state
            if state:
                log.info("conectado al servidor %s", self.base_url)
            else:
                log.warning("sin conexion con el servidor %s %s", self.base_url, detail)

    def _register(self):
        try:
            response = self._post("/api/v1/agents/register", self._envelope([]))
            if response.status_code == 200:
                self._set_connected(True)
                self._last_contact = time.monotonic()
            elif response.status_code in AUTH_STATUS:
                log.error("el servidor rechazo la firma: revisa secret_key y la hora del sistema")
            else:
                log.warning("registro respondio HTTP %s", response.status_code)
        except requests.RequestException as exc:
            self._set_connected(False, f"({exc.__class__.__name__})")

    def _processor(self):
        window_start = time.monotonic()
        sent = 0
        skipped = 0
        while True:
            if self.stop_event.is_set() and self.queue.empty():
                break
            try:
                event = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            now = time.monotonic()
            if now - window_start >= 60:
                if skipped:
                    log.warning("telemetria limitada: %d eventos omitidos en el ultimo minuto", skipped)
                if self.dropped:
                    log.warning("cola saturada: %d eventos descartados", self.dropped)
                    self.dropped = 0
                window_start, sent, skipped = now, 0, 0
            etype = event.get("type")
            try:
                if etype == "system_metrics":
                    self.buffer.save(event)
                    continue
                for alert in self.engine.evaluate(event):
                    log.warning("ALERTA [%s] %s: %s", alert["severity"], alert["rule_id"], alert["message"])
                    self.buffer.save({
                        "uid": uuid.uuid4().hex,
                        "type": "alert",
                        "timestamp": event["timestamp"],
                        "alert": alert,
                    })
                if etype in self.forward and not event.get("preexisting"):
                    if sent < self.max_per_minute:
                        self.buffer.save(event)
                        sent += 1
                    else:
                        skipped += 1
            except Exception:
                log.exception("error procesando evento")

    def _sender(self):
        batch_size = int(self.cfg["server"]["batch_size"])
        interval = float(self.cfg["server"]["send_interval"])
        heartbeat = float(self.cfg["agent"]["heartbeat_interval"])
        backoff = 0.0
        while not self.stop_event.is_set():
            batch = self.buffer.fetch_pending(batch_size)
            heartbeat_due = time.monotonic() - self._last_contact >= heartbeat
            if not batch and not heartbeat_due:
                self.stop_event.wait(interval)
                continue
            ids = [row_id for row_id, _ in batch]
            try:
                response = self._post("/api/v1/events", self._envelope([e for _, e in batch]))
            except requests.RequestException as exc:
                self._set_connected(False, f"({exc.__class__.__name__})")
                backoff = min(max(backoff * 2, 2.0), 60.0)
                self.stop_event.wait(backoff)
                continue
            if response.status_code == 200:
                self.buffer.delete(ids)
                self._set_connected(True)
                self._last_contact = time.monotonic()
                backoff = 0.0
                if len(batch) >= batch_size:
                    continue
            elif response.status_code in DROP_STATUS:
                log.error("el servidor rechazo un lote (HTTP %s); se descartan %d eventos", response.status_code, len(ids))
                self.buffer.delete(ids)
            elif response.status_code in AUTH_STATUS:
                self._set_connected(False, "(firma rechazada: revisa secret_key y la hora del sistema)")
                backoff = 30.0
                self.stop_event.wait(backoff)
                continue
            else:
                self._set_connected(False, f"(HTTP {response.status_code})")
                backoff = min(max(backoff * 2, 2.0), 60.0)
                self.stop_event.wait(backoff)
                continue
            self.stop_event.wait(interval)

    def _build_monitors(self):
        cfg = self.cfg["monitors"]
        factories = (
            ("processes", ProcessMonitor),
            ("network", NetworkMonitor),
            ("files", FileMonitor),
            ("system", SystemMonitor),
            ("listening_ports", ListeningPortMonitor),
        )
        for key, cls in factories:
            section = cfg.get(key) or {}
            if not section.get("enabled", True):
                continue
            try:
                self._monitors.append(cls(self.emit, section, self.ctx))
            except Exception:
                log.exception("no se pudo iniciar el monitor '%s'", key)

    def _install_signals(self):
        if threading.current_thread() is not threading.main_thread():
            return
        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is not None:
                signal.signal(sig, lambda *_: self.stop_event.set())

    def run(self):
        self._install_signals()
        log.info("Wolffy Agent %s | id=%s | host=%s | %s", VERSION, self.agent_id, self.hostname, self.os_info)
        if self.engine.errors:
            log.warning("hay %d reglas con errores; ejecuta 'python wolffy.py check-rules'", len(self.engine.errors))
        self._register()
        self._threads = [
            threading.Thread(target=self._processor, name="procesador", daemon=True),
            threading.Thread(target=self._sender, name="envio", daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        self._build_monitors()
        for monitor in self._monitors:
            monitor.start()
        log.info("agente operativo; Ctrl+C para detener")
        try:
            while not self.stop_event.wait(1):
                pass
        finally:
            self.shutdown()

    def shutdown(self):
        self.stop_event.set()
        for monitor in self._monitors:
            monitor.join(timeout=3)
        for thread in self._threads:
            thread.join(timeout=5)
        try:
            self.buffer.close()
        except Exception:
            pass
        log.info("agente detenido")
