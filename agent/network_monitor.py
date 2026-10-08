import ipaddress
import time

import psutil

from .base import BaseMonitor
from .context import norm_path


class NetworkMonitor(BaseMonitor):
    label = "red"

    def __init__(self, emit, config, ctx):
        super().__init__(emit, ctx)
        self.interval = float(config.get("scan_interval", 3))
        self.include_loopback = bool(config.get("include_loopback", False))
        self.seen = set()
        self.first_scan = True
        self._proc_cache = {}
        self._warned_access = False

    def run(self):
        self.log.info("monitor de red activo (intervalo %.1fs)", self.interval)
        while True:
            try:
                self._scan()
            except psutil.AccessDenied:
                if not self._warned_access:
                    self._warned_access = True
                    self.log.warning("sin permisos para listar conexiones; ejecuta el agente con privilegios elevados")
            except Exception:
                self.report_error("error en el escaneo de red")
            if self.wait(self.interval):
                return

    def _process_info(self, pid):
        if pid is None:
            return "", ""
        now = time.monotonic()
        cached = self._proc_cache.get(pid)
        if cached and now - cached[0] < 60:
            return cached[1], cached[2]
        name = exe = ""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = norm_path(proc.exe())
        except (psutil.Error, OSError):
            pass
        if len(self._proc_cache) > 2000:
            self._proc_cache.clear()
        self._proc_cache[pid] = (now, name, exe)
        return name, exe

    def _scan(self):
        current = set()
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.laddr:
                continue
            if conn.pid == self.ctx.own_pid:
                continue
            try:
                remote = ipaddress.ip_address(conn.raddr.ip.split("%")[0])
            except ValueError:
                continue
            if remote.is_loopback and not self.include_loopback:
                continue
            key = (conn.pid, conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
            current.add(key)
            if key in self.seen:
                continue
            name, exe = self._process_info(conn.pid)
            self.emit({
                "type": "network_connect",
                "pid": conn.pid,
                "process_name": name,
                "process_path": exe,
                "local_ip": conn.laddr.ip,
                "local_port": conn.laddr.port,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "remote_is_loopback": remote.is_loopback,
                "remote_is_private": remote.is_private or remote.is_link_local,
                "preexisting": self.first_scan,
            })
        self.seen = current
        self.first_scan = False
