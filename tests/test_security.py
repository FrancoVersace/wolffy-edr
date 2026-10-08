import time
import unittest

from common.security import sign, verify


class SignatureTests(unittest.TestCase):
    def test_roundtrip(self):
        ts = f"{time.time():.3f}"
        self.assertTrue(verify("k", ts, sign("k", ts, b"body"), b"body"))

    def test_wrong_secret(self):
        ts = f"{time.time():.3f}"
        self.assertFalse(verify("k2", ts, sign("k", ts, b"body"), b"body"))

    def test_tampered_body(self):
        ts = f"{time.time():.3f}"
        self.assertFalse(verify("k", ts, sign("k", ts, b"body"), b"other"))

    def test_replay_old_timestamp(self):
        ts = f"{time.time() - 3600:.3f}"
        self.assertFalse(verify("k", ts, sign("k", ts, b"body"), b"body"))

    def test_garbage_timestamp(self):
        self.assertFalse(verify("k", "abc", "sig", b"body"))


if __name__ == "__main__":
    unittest.main()
