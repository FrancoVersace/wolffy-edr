import psutil

from .base import BaseMonitor
from .context import norm_path


class ListeningPortMonitor(BaseMonitor):
    label = "puertos"

    def __init__(self, emit, config, ctx):
        super().__init__(emit, ctx)
        self.interval = float(config.get("scan_interval", 10))
        self.known = set()
        self.first_scan = True
        self._warned_access = False

    def run(self):
        self.log.info("monitor de puertos en escucha activo (intervalo %.0fs)", self.interval)
        while True:
            try:
                self._scan()
            except psutil.AccessDenied:
                if not self._warned_access:
                    self._warned_access = True
                    self.log.warning("sin permisos para listar conexiones; ejecuta el agente con privilegios elevados")
            except Exception:
                self.report_error("error en el escaneo de puertos")
            if self.wait(self.interval):
                return

    def _scan(self):
        current = {}
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != "LISTEN" or not conn.laddr:
                continue
            if conn.pid == self.ctx.own_pid or conn.pid is None:
                continue
            key = (conn.pid, conn.laddr.port)
            if key not in current:
                current[key] = conn

        current_keys = set(current.keys())
        new_keys = current_keys - self.known
        self.known = current_keys

        if self.first_scan:
            self.first_scan = False
            return

        for key in new_keys:
            conn = current[key]
            pid, port = key
            name, exe = self._process_info(pid)
            self.emit({
                "type": "listening_port",
                "pid": pid,
                "port": port,
                "bind_address": conn.laddr.ip,
                "process_name": name,
                "process_path": exe,
            })

    def _process_info(self, pid):
        try:
            proc = psutil.Process(pid)
            return proc.name(), norm_path(proc.exe())
        except (psutil.Error, OSError):
            return "", ""
