import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from common.config import load_server_config
from common.security import sign
from server.api import create_app

SECRET = "test-secret"


def signed(payload, secret=SECRET, ts=None):
    body = json.dumps(payload).encode()
    ts = ts or f"{time.time():.3f}"
    return body, {"X-Wolffy-Timestamp": ts, "X-Wolffy-Signature": sign(secret, ts, body), "Content-Type": "application/json"}


def batch(events, agent="host-1"):
    return {"agent_id": agent, "hostname": "host", "os_info": "Linux", "ip_address": "10.0.0.2", "version": "3", "events": events}


def alert_event(uid=None, severity="high"):
    return {"uid": uid or uuid.uuid4().hex, "type": "alert", "timestamp": "2026-01-01T00:00:00+00:00",
            "alert": {"rule_id": "WLF-1", "rule_name": "t", "severity": severity, "message": "m", "event": {"a": 1}}}


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cfg = load_server_config()
        cfg["server"]["secret_key"] = SECRET
        cfg["server"]["dashboard_token"] = ""
        self.app = create_app(cfg, Path(self.tmp.name) / "t.db")
        self.client = TestClient(self.app)

    def tearDown(self):
        self.client.close()
        self.tmp.cleanup()

    def post(self, path, payload, **kw):
        body, headers = signed(payload, **kw)
        return self.client.post(path, content=body, headers=headers)

    def test_health(self):
        self.assertEqual(self.client.get("/health").json()["status"], "healthy")

    def test_rejects_unsigned(self):
        self.assertEqual(self.client.post("/api/v1/events", json=batch([])).status_code, 401)

    def test_rejects_bad_signature(self):
        self.assertEqual(self.post("/api/v1/events", batch([]), secret="wrong").status_code, 401)

    def test_rejects_old_timestamp(self):
        self.assertEqual(self.post("/api/v1/events", batch([]), ts=f"{time.time() - 4000:.3f}").status_code, 401)

    def test_register_and_list_agent(self):
        self.assertEqual(self.post("/api/v1/agents/register", batch([])).status_code, 200)
        agents = self.client.get("/api/v1/agents").json()
        self.assertEqual(agents[0]["id"], "host-1")
        self.assertEqual(agents[0]["status"], "online")

    def test_invalid_agent_id(self):
        self.assertEqual(self.post("/api/v1/events", batch([], agent="bad id!")).status_code, 422)

    def test_alert_ingest_and_dedupe(self):
        ev = alert_event("u1")
        self.assertEqual(self.post("/api/v1/events", batch([ev])).json()["alerts"], 1)
        second = self.post("/api/v1/events", batch([ev])).json()
        self.assertEqual(second["duplicates"], 1)
        self.assertEqual(self.client.get("/api/v1/alerts").json()["total"], 1)

    def test_ack_flow(self):
        self.post("/api/v1/events", batch([alert_event()]))
        alert_id = self.client.get("/api/v1/alerts").json()["items"][0]["id"]
        self.assertTrue(self.client.post(f"/api/v1/alerts/{alert_id}/ack").json()["acknowledged"])
        self.assertEqual(self.client.get("/api/v1/alerts?acknowledged=false").json()["total"], 0)
        self.assertEqual(self.client.post("/api/v1/alerts/999/ack").status_code, 404)

    def test_stats_counts_open_only(self):
        self.post("/api/v1/events", batch([alert_event(severity="critical"), alert_event(severity="high")]))
        stats = self.client.get("/api/v1/stats").json()
        self.assertEqual(stats["alerts"]["open_by_severity"]["critical"], 1)
        self.assertEqual(self.client.post("/api/v1/alerts/ack-all").json()["acknowledged"], 2)
        self.assertEqual(self.client.get("/api/v1/stats").json()["alerts"]["open"], 0)

    def test_event_and_metric_ingest(self):
        events = [
            {"uid": "e1", "type": "process_start", "timestamp": "2026-01-01T00:00:00+00:00", "name": "ls"},
            {"type": "system_metrics", "cpu_percent": 5, "memory_percent": 40, "disk_percent": 10},
        ]
        self.assertEqual(self.post("/api/v1/events", batch(events)).json()["accepted"], 2)
        self.assertEqual(self.client.get("/api/v1/events?event_type=process_start").json()["total"], 1)
        self.assertEqual(len(self.client.get("/api/v1/agents/host-1/metrics").json()), 1)

    def test_invalid_filters(self):
        self.assertEqual(self.client.get("/api/v1/alerts?severity=bogus").status_code, 422)
        self.assertEqual(self.client.get("/api/v1/alerts?limit=100000").status_code, 422)

    def test_dashboard_token_enforced(self):
        cfg = load_server_config()
        cfg["server"]["secret_key"] = SECRET
        cfg["server"]["dashboard_token"] = "tok"
        client = TestClient(create_app(cfg, Path(self.tmp.name) / "t2.db"))
        self.assertEqual(client.get("/api/v1/stats").status_code, 401)
        self.assertEqual(client.get("/api/v1/stats", headers={"Authorization": "Bearer tok"}).status_code, 200)
        self.assertEqual(client.get("/health").status_code, 200)
        client.close()

    def test_rules_endpoint(self):
        data = self.client.get("/api/v1/rules").json()
        self.assertEqual(data["errors"], [])
        self.assertGreater(len(data["items"]), 15)

    def test_dashboard_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Wolffy", response.text)


if __name__ == "__main__":
    unittest.main()
