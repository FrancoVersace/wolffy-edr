import hashlib
import os
import posixpath
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .base import BaseMonitor
from .context import norm_path
from .watch_defaults import specs_from_config

MAX_HASH_SIZE = 5 * 1024 * 1024
RESCAN_SECONDS = 30
IGNORED_PARTS = (
    "/.cache/", "/node_modules/", "/.git/", "/__pycache__/", "/.mozilla/",
    "/.config/google-chrome/", "/.config/chromium/", "/.local/share/trash/",
    "/.var/app/", "/.thumbnails/", "/.vscode-server/", "/appdata/local/temp/",
)
IGNORED_SUFFIXES = (
    ".swp", ".swx", ".swo", ".tmp", ".part", ".crdownload", ".pyc", ".lock", "~",
)


def sha256_file(path):
    try:
        if os.path.getsize(path) > MAX_HASH_SIZE:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, event):
        self.monitor.handle("created", event.src_path, event.is_directory)

    def on_modified(self, event):
        self.monitor.handle("modified", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self.monitor.handle("deleted", event.src_path, event.is_directory)

    def on_moved(self, event):
        self.monitor.handle("moved", event.dest_path, event.is_directory, src=event.src_path)


class FileMonitor(BaseMonitor):
    label = "archivos"

    def __init__(self, emit, config, ctx):
        super().__init__(emit, ctx)
        self.debounce = float(config.get("debounce", 1.5))
        self.specs = specs_from_config(config)
        self._ordered = sorted(self.specs, key=lambda s: len(s.path), reverse=True)
        extra = [str(p).lower() for p in (config.get("ignore_patterns") or [])]
        self.ignore_parts = IGNORED_PARTS + tuple(extra)
        self.hashes = {}
        self.attached = set()
        self.warned = set()
        self.recent = {}
        self.observer = Observer()
        self.handler = _Handler(self)

    def run(self):
        self._attach_missing()
        self.observer.start()
        self.log.info("monitor de archivos activo (%d rutas)", len(self.attached))
        next_scan = time.monotonic() + RESCAN_SECONDS
        while not self.wait(2):
            now = time.monotonic()
            if now >= next_scan:
                next_scan = now + RESCAN_SECONDS
                self._attach_missing()
                self._prune_recent(now)
        self.observer.stop()
        self.observer.join(3)

    def _attach_missing(self):
        for spec in self.specs:
            key = (spec.path, spec.names)
            if key in self.attached or not os.path.isdir(spec.path):
                continue
            if not self._schedule(spec):
                continue
            self.attached.add(key)
            self._baseline(spec)

    def _schedule(self, spec):
        try:
            self.observer.schedule(self.handler, spec.path, recursive=spec.recursive)
            return True
        except OSError as exc:
            first_error = exc
        except Exception:
            self.report_error("error vigilando %s", spec.path)
            return False
        if spec.recursive:
            try:
                self.observer.schedule(self.handler, spec.path, recursive=False)
                self._warn_once(spec.path, "%s se vigila sin recursividad: %s", spec.path, first_error)
                return True
            except OSError:
                pass
        self._warn_once(
            spec.path,
            "no se pudo vigilar %s (%s); si es el limite de inotify, aumenta fs.inotify.max_user_watches",
            spec.path, first_error,
        )
        return False

    def _warn_once(self, key, message, *args):
        if key not in self.warned:
            self.warned.add(key)
            self.log.warning(message, *args)

    def _baseline(self, spec):
        if not spec.hash:
            return
        try:
            names = spec.names or [e.name for e in os.scandir(spec.path) if e.is_file()][:500]
        except OSError:
            return
        for name in names:
            full = f"{spec.path.rstrip('/')}/{name}"
            if os.path.isfile(full):
                digest = sha256_file(full)
                if digest:
                    self.hashes[full] = digest

    def _prune_recent(self, now):
        cutoff = now - 60
        self.recent = {k: v for k, v in self.recent.items() if v > cutoff}

    def _spec_for(self, path):
        parent = posixpath.dirname(path)
        for spec in self._ordered:
            base = spec.path.rstrip("/")
            if spec.recursive:
                if path.startswith(base + "/"):
                    return spec
            elif parent == base or (not base and parent == "/"):
                return spec
        return None

    def _ignored(self, path):
        lowered = path.lower()
        if self.ctx.data_dir and lowered.startswith(self.ctx.data_dir):
            return True
        if lowered.endswith(IGNORED_SUFFIXES):
            return True
        return any(part in lowered for part in self.ignore_parts)

    def handle(self, action, raw_path, is_directory, src=None):
        if is_directory or self.ctx.stop.is_set():
            return
        try:
            self._process_file(action, norm_path(raw_path), norm_path(src) if src else None)
        except Exception:
            self.report_error("error procesando evento de archivo")

    def _process_file(self, action, path, src):
        if self._ignored(path):
            return
        spec = self._spec_for(path)
        if spec is None:
            return
        filename = posixpath.basename(path)
        if filename == "4913":
            return
        if spec.names and filename.lower() not in spec.names:
            return
        now = time.monotonic()
        key = (path, action)
        last = self.recent.get(key)
        if last is not None and now - last < self.debounce:
            return
        self.recent[key] = now

        changed = True
        digest = None
        if src:
            self.hashes.pop(src, None)
        if spec.hash:
            if action == "deleted":
                self.hashes.pop(path, None)
            else:
                digest = sha256_file(path)
                if digest is not None:
                    if self.hashes.get(path) == digest:
                        return
                    self.hashes[path] = digest
        event = {
            "type": "file_event",
            "action": action,
            "path": path,
            "directory": posixpath.dirname(path),
            "filename": filename,
            "extension": os.path.splitext(filename)[1].lower(),
            "content_changed": changed,
            "pkg_activity": self.ctx.pkg_active,
        }
        if src:
            event["src_path"] = src
        if digest:
            event["sha256"] = digest
        self.emit(event)
