import hmac
import hashlib
import os
import secrets
import time

from .paths import DATA_DIR, ensure_dirs

MAX_CLOCK_SKEW = 300
PLACEHOLDER_SECRETS = {"", "change-me", "changeme", "wolffy_secret_key_change_in_production"}


def _read_or_create(path):
    ensure_dirs()
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = secrets.token_hex(32)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
    return value


def resolve_secret(configured=None):
    env = os.environ.get("WOLFFY_SECRET")
    if env:
        return env
    if configured and str(configured) not in PLACEHOLDER_SECRETS:
        return str(configured)
    return _read_or_create(DATA_DIR / "secret.key")


def resolve_dashboard_token(configured, host):
    if configured:
        return str(configured)
    if host in ("127.0.0.1", "localhost", "::1"):
        return ""
    return _read_or_create(DATA_DIR / "dashboard.token")


def sign(secret, timestamp, body):
    message = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify(secret, timestamp, signature, body, max_skew=MAX_CLOCK_SKEW):
    try:
        skew = abs(time.time() - float(timestamp))
    except (TypeError, ValueError):
        return False
    if skew > max_skew:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature or "")
