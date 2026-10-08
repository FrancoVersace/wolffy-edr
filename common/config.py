import copy
import os
from pathlib import Path

import yaml

from .paths import CONFIG_DIR


class ConfigError(Exception):
    pass


AGENT_DEFAULTS = {
    "agent": {
        "rules_file": "rules.yaml",
        "heartbeat_interval": 30,
    },
    "server": {
        "url": "http://127.0.0.1:8000",
        "secret_key": "",
        "send_interval": 3,
        "batch_size": 200,
        "timeout": 10,
        "verify_tls": True,
        "ca_bundle": "",
    },
    "buffer": {"max_events": 50000},
    "telemetry": {
        "forward": ["process_start", "network_connect", "file_event", "listening_port"],
        "max_per_minute": 300,
    },
    "allowlist": {
        "rule_ids": [],
        "process_names": [],
        "paths": [],
        "command_patterns": [],
    },
    "monitors": {
        "processes": {"enabled": True, "scan_interval": 0.5, "capture_cmdline": True},
        "files": {
            "enabled": True,
            "paths": "auto",
            "extra_paths": [],
            "ignore_patterns": [],
            "debounce": 1.5,
        },
        "network": {"enabled": True, "scan_interval": 3, "include_loopback": False},
        "system": {"enabled": True, "scan_interval": 30},
        "listening_ports": {"enabled": True, "scan_interval": 10},
    },
}

SERVER_DEFAULTS = {
    "server": {
        "host": "127.0.0.1",
        "port": 8000,
        "secret_key": "",
        "dashboard_token": "",
        "agent_offline_after": 90,
    },
    "database": {"path": ""},
    "rules": {"file": "rules.yaml"},
    "retention": {
        "events_days": 7,
        "metrics_days": 7,
        "alerts_days": 180,
        "max_events": 200000,
    },
    "notifications": {
        "ntfy_topic": "",  # e.g. "wolffy_edr_alerts"
        "min_severity": "high",  # only send alerts >= this severity
    },
}


def deep_merge(base, override):
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_yaml(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML invalido en {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path} debe contener un mapa YAML en la raiz")
    return data


def resolve_path(value, base=CONFIG_DIR):
    candidate = Path(os.path.expanduser(str(value)))
    return candidate if candidate.is_absolute() else Path(base) / candidate


def load_agent_config(path=None):
    cfg = deep_merge(AGENT_DEFAULTS, load_yaml(path or CONFIG_DIR / "agent.yaml"))
    url = os.environ.get("WOLFFY_SERVER_URL") or cfg["server"]["url"]
    url = str(url).rstrip("/")
    for suffix in ("/api/events", "/api/v1/events"):
        if url.endswith(suffix):
            url = url[: -len(suffix)]
    cfg["server"]["url"] = url
    return cfg


def load_server_config(path=None):
    cfg = deep_merge(SERVER_DEFAULTS, load_yaml(path or CONFIG_DIR / "server.yaml"))
    if os.environ.get("WOLFFY_HOST"):
        cfg["server"]["host"] = os.environ["WOLFFY_HOST"]
    if os.environ.get("WOLFFY_PORT"):
        cfg["server"]["port"] = int(os.environ["WOLFFY_PORT"])
    if os.environ.get("WOLFFY_DASHBOARD_TOKEN"):
        cfg["server"]["dashboard_token"] = os.environ["WOLFFY_DASHBOARD_TOKEN"]
    return cfg
