import os
import threading
import time


class Context:
    def __init__(self, stop_event=None, data_dir=""):
        self.stop = stop_event or threading.Event()
        self.own_pid = os.getpid()
        self.data_dir = norm_path(str(data_dir)).lower()
        self._pkg_until = 0.0

    def mark_package_activity(self, ttl=120.0):
        self._pkg_until = max(self._pkg_until, time.monotonic() + ttl)

    @property
    def pkg_active(self):
        return time.monotonic() < self._pkg_until


def norm_path(path):
    if not path:
        return ""
    path = str(path)
    if os.name == "nt":
        path = path.replace("\\", "/")
    return path
