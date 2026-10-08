import os

import psutil

from .base import BaseMonitor


class SystemMonitor(BaseMonitor):
    label = "sistema"

    def __init__(self, emit, config, ctx):
        super().__init__(emit, ctx)
        self.interval = float(config.get("scan_interval", 30))
        self.disk_root = os.path.abspath(os.sep)

    def run(self):
        self.log.info("monitor de sistema activo (intervalo %.0fs)", self.interval)
        psutil.cpu_percent(interval=None)
        if self.wait(min(self.interval, 3)):
            return
        while True:
            try:
                self.emit({
                    "type": "system_metrics",
                    "cpu_percent": psutil.cpu_percent(interval=None),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage(self.disk_root).percent,
                })
            except Exception:
                self.report_error("error leyendo metricas del sistema")
            if self.wait(self.interval):
                return
