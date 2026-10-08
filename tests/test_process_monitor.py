import os
import tempfile
import unittest

from agent.process_monitor import script_target


class ScriptTargetTests(unittest.TestCase):
    def test_shell_with_script(self):
        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as handle:
            path = handle.name
        try:
            self.assertEqual(script_target("/bin/bash", ["bash", path], "/"), os.path.normpath(path))
        finally:
            os.unlink(path)

    def test_shell_with_inline_code_keeps_exe(self):
        self.assertEqual(script_target("/bin/sh", ["sh", "-c", "echo hi"], "/tmp"), "/bin/sh")

    def test_non_interpreter(self):
        self.assertEqual(script_target("/usr/bin/ls", ["ls", "/tmp"], "/"), "/usr/bin/ls")

    def test_python_module_keeps_exe(self):
        self.assertEqual(script_target("/usr/bin/python3", ["python3", "-m", "http.server"], "/tmp"), "/usr/bin/python3")


if __name__ == "__main__":
    unittest.main()
