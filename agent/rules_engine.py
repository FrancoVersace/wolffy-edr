from __future__ import annotations

import logging
import os
import re
import sys
import time
from collections import deque
from pathlib import Path

import yaml

log = logging.getLogger("wolffy.rules")

SEVERITIES = ("low", "medium", "high", "critical")
MAX_FIELD_LEN = 2000
IDENTITY_FIELDS = (
    "name", "target", "cmdline", "path", "action",
    "remote_ip", "remote_port", "process_name", "process_path",
)

_LIST_OPS = {"in", "not_in", "contains_any", "startswith_any", "endswith_any"}
_NUM_OPS = {"gt", "gte", "lt", "lte"}
_ALL_OPS = _LIST_OPS | _NUM_OPS | {
    "eq", "ne", "contains", "startswith", "endswith", "regex", "exists", "out_of_hours",
}


class RuleError(ValueError):
    pass


def current_platform():
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("win"):
        return "windows"
    return sys.platform


def _text(value):
    return "" if value is None else str(value).lower()


def _get(event, dotted):
    value = event
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _compile_leaf(node):
    field = node.get("field")
    op = node.get("op")
    if not isinstance(field, str) or not field:
        raise RuleError("condicion sin 'field'")
    if op not in _ALL_OPS:
        raise RuleError(f"operador desconocido: {op!r}")
    if op not in ("exists", "out_of_hours") and "value" not in node:
        raise RuleError(f"condicion '{field} {op}' sin 'value'")
    value = node.get("value")

    if op == "out_of_hours":
        # expects value like "08:00-15:00"
        try:
            start_h, end_h = [int(x.split(":")[0]) for x in str(value).split("-")]
        except Exception:
            raise RuleError("'out_of_hours' debe tener formato 'HH:MM-HH:MM'")
        def check_time(ev):
            import time
            h = time.localtime().tm_hour
            if start_h <= end_h:
                return not (start_h <= h < end_h)
            return not (start_h <= h or h < end_h)
        return check_time

    if op == "exists":
        want = True if value is None else bool(value)
        return lambda ev: (_get(ev, field) is not None) == want

    if op in _LIST_OPS:
        if not isinstance(value, list) or not value:
            raise RuleError(f"'{op}' requiere una lista no vacia")
        items = [_text(v) for v in value]
        if op in ("in", "not_in"):
            pool = set(items)
            if op == "in":
                return lambda ev: _text(_get(ev, field)) in pool and _get(ev, field) is not None
            return lambda ev: _get(ev, field) is None or _text(_get(ev, field)) not in pool
        needles = tuple(items)
        if op == "contains_any":
            return lambda ev: any(n in _text(_get(ev, field)) for n in needles)
        if op == "startswith_any":
            return lambda ev: _text(_get(ev, field)).startswith(needles)
        return lambda ev: _text(_get(ev, field)).endswith(needles)

    if op in _NUM_OPS:
        try:
            limit = float(value)
        except (TypeError, ValueError):
            raise RuleError(f"'{op}' requiere un numero") from None
        compare = {
            "gt": lambda a: a > limit, "gte": lambda a: a >= limit,
            "lt": lambda a: a < limit, "lte": lambda a: a <= limit,
        }[op]

        def numeric(ev):
            try:
                return compare(float(_get(ev, field)))
            except (TypeError, ValueError):
                return False
        return numeric

    if op == "regex":
        try:
            pattern = re.compile(str(value), re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            raise RuleError(f"regex invalida ({exc})") from None

        def regex(ev):
            actual = _get(ev, field)
            return actual is not None and pattern.search(str(actual)) is not None
        return regex

    expected = _text(value)
    if op == "eq":
        return lambda ev: _get(ev, field) is not None and _text(_get(ev, field)) == expected
    if op == "ne":
        return lambda ev: _get(ev, field) is None or _text(_get(ev, field)) != expected
    if op == "contains":
        return lambda ev: expected in _text(_get(ev, field))
    if op == "startswith":
        return lambda ev: _text(_get(ev, field)).startswith(expected)
    return lambda ev: _text(_get(ev, field)).endswith(expected)


def _compile(node):
    if isinstance(node, list):
        if not node:
            raise RuleError("lista de condiciones vacia")
        parts = [_compile(item) for item in node]
        return lambda ev: all(p(ev) for p in parts)
    if not isinstance(node, dict):
        raise RuleError("cada condicion debe ser un mapa o una lista")
    if "all" in node:
        parts = [_compile(item) for item in _as_list(node["all"])]
        return lambda ev: all(p(ev) for p in parts)
    if "any" in node:
        parts = [_compile(item) for item in _as_list(node["any"])]
        return lambda ev: any(p(ev) for p in parts)
    if "not" in node:
        inner = _compile(node["not"])
        return lambda ev: not inner(ev)
    return _compile_leaf(node)


def _as_list(value):
    if not isinstance(value, list) or not value:
        raise RuleError("'all'/'any' requieren una lista no vacia")
    return value


class Rule:
    __slots__ = (
        "id", "name", "description", "severity", "event_type", "platforms",
        "mitre", "match", "exclude", "threshold", "cooldown", "dedupe_by",
        "message", "enabled",
    )


def parse_rule(raw):
    if not isinstance(raw, dict):
        raise RuleError("la regla debe ser un mapa")
    rule = Rule()
    rule.id = str(raw.get("id") or "").strip()
    if not rule.id:
        raise RuleError("falta 'id'")
    rule.name = str(raw.get("name") or "").strip()
    if not rule.name:
        raise RuleError("falta 'name'")
    rule.description = str(raw.get("description") or "")
    rule.enabled = bool(raw.get("enabled", True))
    rule.severity = str(raw.get("severity") or "medium").lower()
    if rule.severity not in SEVERITIES:
        raise RuleError(f"severity invalida: {rule.severity!r}")
    rule.event_type = str(raw.get("event_type") or "").strip()
    if not rule.event_type:
        raise RuleError("falta 'event_type'")
    platforms = raw.get("platforms") or []
    if not isinstance(platforms, list):
        raise RuleError("'platforms' debe ser una lista")
    rule.platforms = {str(p).lower() for p in platforms}
    rule.mitre = str(raw["mitre"]) if raw.get("mitre") else None
    if "match" not in raw:
        raise RuleError("falta 'match'")
    rule.match = _compile(raw["match"])
    rule.exclude = _compile(raw["exclude"]) if raw.get("exclude") else None
    rule.threshold = _parse_threshold(raw.get("threshold"))
    try:
        rule.cooldown = float(raw.get("cooldown", 60))
    except (TypeError, ValueError):
        raise RuleError("'cooldown' debe ser numerico") from None
    dedupe = raw.get("dedupe_by")
    if dedupe is not None and not (isinstance(dedupe, list) and all(isinstance(d, str) for d in dedupe)):
        raise RuleError("'dedupe_by' debe ser una lista de campos")
    rule.dedupe_by = tuple(dedupe) if dedupe else None
    rule.message = str(raw.get("message") or rule.name)
    return rule


def _parse_threshold(raw):
    if not raw:
        return None
    if not isinstance(raw, dict):
        raise RuleError("'threshold' debe ser un mapa")
    try:
        count = int(raw["count"])
        window = float(raw["window"])
    except (KeyError, TypeError, ValueError):
        raise RuleError("'threshold' requiere 'count' y 'window' numericos") from None
    if count < 2 or window <= 0:
        raise RuleError("'threshold.count' debe ser >= 2 y 'window' > 0")
    group_by = raw.get("group_by") or []
    if not isinstance(group_by, list):
        raise RuleError("'threshold.group_by' debe ser una lista")
    return {
        "count": count,
        "window": window,
        "group_by": [str(g) for g in group_by],
        "distinct": raw.get("distinct"),
    }


def load_rules(path):
    rules, errors, seen = [], [], set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return [], [f"archivo de reglas no encontrado: {path}"]
    except yaml.YAMLError as exc:
        return [], [f"YAML invalido en {path}: {exc}"]
    raw_rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(raw_rules, list):
        return [], [f"{path}: se esperaba una clave 'rules' con una lista"]
    for index, raw in enumerate(raw_rules, start=1):
        label = raw.get("id", f"#{index}") if isinstance(raw, dict) else f"#{index}"
        try:
            rule = parse_rule(raw)
            if rule.id in seen:
                raise RuleError(f"id duplicado: {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
        except RuleError as exc:
            errors.append(f"regla {label}: {exc}")
    return rules, errors


class _Allowlist:
    def __init__(self, cfg):
        cfg = cfg or {}
        self.rule_ids = {str(x) for x in (cfg.get("rule_ids") or [])}
        self.names = {str(x).lower() for x in (cfg.get("process_names") or [])}
        self.paths = tuple(
            self._norm(x) for x in (cfg.get("paths") or [])
        )
        self.patterns = [re.compile(str(p), re.IGNORECASE) for p in (cfg.get("command_patterns") or [])]

    @staticmethod
    def _norm(path):
        path = os.path.expanduser(str(path))
        if os.name == "nt":
            path = path.replace("\\", "/")
        return path.lower()

    def matches(self, event):
        name = _text(event.get("name") or event.get("process_name"))
        if name and name in self.names:
            return True
        if self.paths:
            for key in ("path", "target", "exe", "process_path"):
                value = event.get(key)
                if value and _text(value).startswith(self.paths):
                    return True
        cmdline = event.get("cmdline")
        if cmdline and any(p.search(cmdline) for p in self.patterns):
            return True
        return False


class _SafeDict(dict):
    def __missing__(self, key):
        return "?"


def _shorten(value, limit=MAX_FIELD_LEN):
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "..."
    return value


class RulesEngine:
    def __init__(self, rules_path, allowlist=None, platform_name=None, reload_interval=5.0):
        self.path = Path(rules_path)
        self.platform = platform_name or current_platform()
        self.allow = _Allowlist(allowlist)
        self.reload_interval = reload_interval
        self.errors = []
        self.total_rules = 0
        self._by_type = {}
        self._mtime = None
        self._last_check = 0.0
        self._last_fired = {}
        self._windows = {}
        self.reload(force=True)

    @property
    def active_rules(self):
        return sum(len(v) for v in self._by_type.values())

    def reload(self, force=False):
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            mtime = None
        if not force and mtime == self._mtime:
            return
        self._mtime = mtime
        rules, errors = load_rules(self.path)
        for message in errors:
            log.error("reglas: %s", message)
        by_type = {}
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.platforms and self.platform not in rule.platforms:
                continue
            by_type.setdefault(rule.event_type, []).append(rule)
        self.errors = errors
        self.total_rules = len(rules)
        self._by_type = by_type
        log.info("reglas cargadas: %d activas de %d (%s)", self.active_rules, len(rules), self.platform)

    def _maybe_reload(self):
        now = time.monotonic()
        if now - self._last_check >= self.reload_interval:
            self._last_check = now
            self.reload()

    def evaluate(self, event):
        self._maybe_reload()
        rules = self._by_type.get(event.get("type"))
        if not rules or self.allow.matches(event):
            return []
        now = time.monotonic()
        alerts = []
        for rule in rules:
            if rule.id in self.allow.rule_ids:
                continue
            try:
                if not rule.match(event):
                    continue
                if rule.exclude is not None and rule.exclude(event):
                    continue
            except Exception:
                log.debug("error evaluando regla %s", rule.id, exc_info=True)
                continue
            count = 1
            if rule.threshold is not None:
                count = self._threshold(rule, event, now)
                if not count:
                    continue
            if self._suppressed(rule, event, now):
                continue
            alerts.append(self._build_alert(rule, event, count))
        return alerts

    def _threshold(self, rule, event, now):
        spec = rule.threshold
        key = (rule.id, tuple(str(_get(event, f)) for f in spec["group_by"]))
        window = self._windows.setdefault(key, deque())
        distinct = spec["distinct"]
        window.append((now, str(_get(event, distinct)) if distinct else None))
        cutoff = now - spec["window"]
        while window and window[0][0] < cutoff:
            window.popleft()
        count = len({v for _, v in window}) if distinct else len(window)
        if len(self._windows) > 500:
            self._prune_windows(now)
        if count >= spec["count"]:
            window.clear()
            return count
        return 0

    def _prune_windows(self, now):
        for key in [k for k, w in self._windows.items() if not w or now - w[-1][0] > 3600]:
            del self._windows[key]

    def _suppressed(self, rule, event, now):
        if rule.cooldown <= 0:
            return False
        fields = rule.dedupe_by if rule.dedupe_by is not None else IDENTITY_FIELDS
        if rule.threshold is not None and rule.dedupe_by is None:
            fields = tuple(rule.threshold["group_by"])
        key = (rule.id, tuple(str(_get(event, f)) for f in fields))
        last = self._last_fired.get(key)
        if last is not None and now - last < rule.cooldown:
            return True
        self._last_fired[key] = now
        if len(self._last_fired) > 4000:
            expiry = now - 3600
            self._last_fired = {k: v for k, v in self._last_fired.items() if v > expiry}
        return False

    @staticmethod
    def _build_alert(rule, event, count):
        context = _SafeDict({k: _shorten(v) for k, v in event.items() if not isinstance(v, (dict, list))})
        context["count"] = count
        try:
            message = rule.message.format_map(context)
        except (ValueError, IndexError, KeyError, AttributeError):
            message = rule.message
        return {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "message": message,
            "mitre_attack": rule.mitre,
            "event": {k: _shorten(v) for k, v in event.items()},
        }
