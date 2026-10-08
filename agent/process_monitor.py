import os
import re
import psutil

from .base import BaseMonitor
from .context import norm_path

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish"}
PYTHONS = re.compile(r"^python[\d.]*$")
OTHER_INTERPRETERS = {"perl", "ruby", "node", "php", "lua", "pwsh", "powershell"}
CODE_FLAGS = {"shell": "c", "python": "cm", "other": "eEr"}

PACKAGE_MANAGERS = {
    "dpkg", "apt", "apt-get", "aptitude", "rpm", "dnf", "yum", "pacman",
    "zypper", "snapd", "packagekitd", "unattended-upgr", "fwupd", "brew",
    "msiexec", "choco",
}


def _interpreter_kind(base):
    if base in SHELLS:
        return "shell"
    if PYTHONS.match(base):
        return "python"
    if base in OTHER_INTERPRETERS:
        return "other"
    return None


def script_target(exe, cmdline, cwd):
    base = os.path.basename(exe or "").lower()
    if base.endswith(".exe"):
        base = base[:-4]
    kind = _interpreter_kind(base)
    if kind is None or len(cmdline) < 2:
        return exe
    code_flags = CODE_FLAGS[kind]
    for arg in cmdline[1:]:
        if arg.startswith("-"):
            if re.match(r"^-[A-Za-z]*[%s]$" % code_flags, arg):
                return exe
            continue
        candidate = arg if os.path.isabs(arg) else (os.path.join(cwd, arg) if cwd else None)
        if candidate and os.path.isfile(candidate):
            return os.path.normpath(candidate)
        return exe
    return exe


class ProcessMonitor(BaseMonitor):
    label = "procesos"

    def __init__(self, emit, config, ctx):
        super().__init__(emit, ctx)
        self.interval = float(config.get("scan_interval", 0.5))
        self.capture_cmdline = bool(config.get("capture_cmdline", True))
        self.known = set(psutil.pids())

    def run(self):
        self.log.info("monitor de procesos activo (intervalo %.2fs)", self.interval)
        while not self.wait(self.interval):
            try:
                self._scan()
            except Exception:
                self.report_error("error en el escaneo de procesos")

    def _scan(self):
        current = set(psutil.pids())
        new = current - self.known
        self.known = current
        for pid in new:
            if pid == self.ctx.own_pid:
                continue
            event = self._build_event(pid)
            if event is not None:
                self.emit(event)

    def _build_event(self, pid):
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                info = proc.as_dict(attrs=["name", "exe", "cmdline", "ppid", "username"])
                name = (info.get("name") or "").strip()
                exe = norm_path(info.get("exe") or "")
                cmdline = info.get("cmdline") or []
                if not name or (not exe and not cmdline):
                    return None
                if info.get("ppid") == self.ctx.own_pid:
                    return None
                cwd = None
                if _interpreter_kind(os.path.basename(exe).lower().replace(".exe", "")):
                    try:
                        cwd = proc.cwd()
                    except (psutil.Error, OSError):
                        cwd = None
                parent_name = ""
                try:
                    parent_name = psutil.Process(info["ppid"]).name() if info.get("ppid") else ""
                except (psutil.Error, OSError):
                    pass
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            return None

        if name.lower().endswith(".exe"):
            name = name[:-4]
        if name.lower() in PACKAGE_MANAGERS or parent_name.lower() in PACKAGE_MANAGERS:
            self.ctx.mark_package_activity()

        target = script_target(exe, cmdline, cwd)
        event = {
            "type": "process_start",
            "pid": pid,
            "ppid": info.get("ppid"),
            "name": name,
            "exe": exe,
            "target": norm_path(target),
            "username": info.get("username") or "",
            "parent_name": parent_name,
            "pkg_activity": self.ctx.pkg_active,
        }
        if self.capture_cmdline:
            event["cmdline"] = " ".join(cmdline)[:4096]
        return event
