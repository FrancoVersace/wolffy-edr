import logging
import threading
import time


class BaseMonitor(threading.Thread):
    label = "monitor"

    def __init__(self, emit, ctx):
        super().__init__(name=self.label, daemon=True)
        self.emit = emit
        self.ctx = ctx
        self.log = logging.getLogger(f"wolffy.{self.label}")
        self._last_error = 0.0

    def wait(self, seconds):
        return self.ctx.stop.wait(seconds)

    def report_error(self, message, *args):
        now = time.monotonic()
        if now - self._last_error > 60:
            self._last_error = now
            self.log.warning(message, *args, exc_info=True)

    def run(self):
        raise NotImplementedError
