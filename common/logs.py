import logging
import logging.handlers

from .paths import LOG_DIR, ensure_dirs

FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(filename, level="INFO"):
    ensure_dirs()
    root = logging.getLogger()
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    for handler in list(root.handlers):
        root.removeHandler(handler)
    formatter = logging.Formatter(FORMAT)
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / filename, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(file_handler)
    root.addHandler(console)
    for noisy in ("urllib3", "watchdog", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
