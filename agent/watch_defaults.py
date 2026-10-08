import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, FrozenSet

from .context import norm_path

PROFILE_NAMES = frozenset({
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".bash_logout",
})
ETC_FILES = frozenset({
    "passwd", "shadow", "group", "gshadow", "sudoers", "ld.so.preload",
    "crontab", "environment", "profile", "bash.bashrc", "rc.local",
})
USER_DATA_DIRS = ("Downloads", "Documents", "Desktop", "Pictures")


@dataclass(frozen=True)
class WatchSpec:
    path: str
    recursive: bool = False
    hash: bool = False
    names: Optional[FrozenSet[str]] = None


def user_homes():
    if os.name == "nt":
        return [Path.home()]
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        is_root = False
    if not is_root:
        return [Path.home()]
    homes = []
    base = Path("/Users") if sys.platform == "darwin" else Path("/home")
    if base.is_dir():
        for child in sorted(base.iterdir()):
            if child.is_dir() and child.name not in ("Shared", "Guest", "lost+found"):
                homes.append(child)
    if sys.platform != "darwin" and Path("/root").is_dir():
        homes.append(Path("/root"))
    return homes or [Path.home()]


def _home_specs(home):
    home = norm_path(str(home))
    specs = []
    if sys.platform != "win32":
        specs.append(WatchSpec(home, False, True, PROFILE_NAMES))
        specs.append(WatchSpec(f"{home}/.ssh", False, True, frozenset({"authorized_keys", "authorized_keys2"})))
        specs.append(WatchSpec(f"{home}/.config/autostart", False, True))
        specs.append(WatchSpec(f"{home}/.config/systemd/user", False, True))
    if sys.platform == "darwin":
        specs.append(WatchSpec(f"{home}/Library/LaunchAgents", False, True))
    for name in USER_DATA_DIRS:
        specs.append(WatchSpec(f"{home}/{name}", True, False))
    return specs


def default_watch_specs():
    specs = []
    if sys.platform.startswith("linux"):
        specs.append(WatchSpec("/etc", False, True, ETC_FILES))
        specs.append(WatchSpec("/etc/ssh", False, True, frozenset({"sshd_config"})))
        for directory in (
            "/etc/sudoers.d", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
            "/etc/cron.weekly", "/etc/cron.monthly", "/etc/pam.d", "/etc/profile.d",
            "/etc/init.d", "/etc/systemd/system",
        ):
            specs.append(WatchSpec(directory, False, True))
        specs.append(WatchSpec("/var/spool/cron", True, True))
    elif sys.platform == "darwin":
        specs.append(WatchSpec("/Library/LaunchAgents", False, True))
        specs.append(WatchSpec("/Library/LaunchDaemons", False, True))
    for home in user_homes():
        specs.extend(_home_specs(home))
    if os.name == "nt":
        for env in ("APPDATA", "PROGRAMDATA"):
            base = os.environ.get(env)
            if base:
                startup = norm_path(os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"))
                specs.append(WatchSpec(startup, False, True))
    return specs


def specs_from_config(config):
    paths = config.get("paths", "auto")
    extra = config.get("extra_paths") or []
    specs = default_watch_specs() if paths in ("auto", None) else []
    entries = list(extra) if paths in ("auto", None) else list(paths or []) + list(extra)
    for entry in entries:
        if isinstance(entry, dict):
            path = entry.get("path")
            recursive = bool(entry.get("recursive", True))
            hashed = bool(entry.get("hash", False))
        else:
            path, recursive, hashed = entry, True, False
        if path:
            specs.append(WatchSpec(norm_path(os.path.expanduser(str(path))).rstrip("/") or "/", recursive, hashed))
    unique = {}
    for spec in specs:
        unique[(spec.path, spec.names)] = spec
    return list(unique.values())
