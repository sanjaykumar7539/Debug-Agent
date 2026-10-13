import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import create_app
from memory import JobStore
from prompt_loader import load_prompts
from logger import configure_logging, close_logging

TOKEN = "test-token-" + "a" * 32

class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = create_app(TOKEN, self.root / "workspace", self.root / "logs")
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.headers = {"X-API-Key": TOKEN}
        self.request = {"files": [{"name": "app.py", "content": "def broken(:"}]}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def test_auth_and_health(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.post("/analyze", json=self.request).status_code, 401)
        self.assertEqual(self.client.get("/debug-status", headers={"X-API-Key": "wrong"}).status_code, 401)
        self.assertEqual(self.client.get("/openapi.json", headers=self.headers).status_code, 200)

    def test_offline_history_report_delete(self):
        with patch("urllib.request.urlopen") as network:
            response = self.client.post("/analyze", json=self.request, headers=self.headers)
            network.assert_not_called()
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["result"]["local_findings"][0]["severity"], "error")
        job_id = data["job_id"]
        self.assertEqual(self.client.get("/debug-status", headers=self.headers).json()["jobs"][0]["id"], job_id)
        self.assertEqual(self.client.get("/debug-status/" + job_id, headers=self.headers).json()["status"], "completed")
        report = self.client.get("/reports/" + job_id, headers=self.headers)
        self.assertEqual(report.status_code, 200)
        self.assertIn("frame-ancestors", report.headers["content-security-policy"])
        self.assertEqual(self.client.delete("/history/" + job_id, headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/debug-status/" + job_id, headers=self.headers).status_code, 404)

    def test_no_source_in_history_or_logs(self):
        marker = "PRIVATE_CONTENT_MARKER_123"
        request = {"files": [{"name": "app.py", "content": "value = '" + marker + "'"}]}
        data = self.client.post("/analyze", json=request, headers=self.headers).json()
        record = self.client.get("/debug-status/" + data["job_id"], headers=self.headers).text
        self.assertNotIn(marker, record)
        self.assertNotIn(marker, (self.root / "logs/agent.jsonl").read_text())

    def test_validation_does_not_echo_input(self):
        bad = {"files": [{"name": "../secret.py", "content": "PRIVATE_PAYLOAD"}]}
        response = self.client.post("/analyze", json=bad, headers=self.headers)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("PRIVATE_PAYLOAD", response.text)
        self.assertEqual(self.client.post("/analyze", json={"path": "/etc/passwd"}, headers=self.headers).status_code, 422)

    def test_duplicate_and_large_sources(self):
        duplicate = {"files": [self.request["files"][0]] * 2}
        self.assertEqual(self.client.post("/analyze", json=duplicate, headers=self.headers).status_code, 422)
        big = {"files": [{"name": "big.py", "content": "a" * 65537}]}
        self.assertEqual(self.client.post("/analyze", json=big, headers=self.headers).status_code, 422)
        self.assertEqual(self.client.post("/analyze", content=b"x" * 1048577, headers=self.headers).status_code, 413)

    def test_cloud_opt_in_required(self):
        request = dict(self.request, online=True)
        self.assertEqual(self.client.post("/analyze", json=request, headers=self.headers).status_code, 422)
        request["allow_cloud_upload"] = True
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.client.post("/analyze", json=request, headers=self.headers).status_code, 503)

    def test_online_success_and_failure(self):
        request = dict(self.request, online=True, allow_cloud_upload=True)
        with patch.dict(os.environ, {"GEMINI_API_KEY": "dummy-test-key"}):
            with patch("main.ai_review", return_value="Suggested fix"):
                response = self.client.post("/analyze", json=request, headers=self.headers)
                self.assertEqual(response.json()["result"]["ai_status"], "completed")
            with patch("main.ai_review", side_effect=RuntimeError("private-provider-detail")):
                response = self.client.post("/analyze", json=request, headers=self.headers)
                self.assertEqual(response.status_code, 502)
                self.assertEqual(response.json()["status"], "failed")
                self.assertNotIn("private-provider-detail", response.text)

    def test_auth_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                create_app()

    def test_rate_limit(self):
        app = create_app(TOKEN, self.root / "w2", self.root / "l2", max_requests=1)
        with TestClient(app) as client:
            self.assertEqual(client.get("/debug-status", headers=self.headers).status_code, 200)
            self.assertEqual(client.get("/debug-status", headers=self.headers).status_code, 429)

class InfrastructureTests(unittest.TestCase):
    def test_prompt_config(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "system_prompt.txt").write_text("Custom system")
            (root / "debug_template.txt").write_text("Evidence: {evidence}")
            with patch.dict(os.environ, {"DEBUG_AGENT_PROMPT_DIR": d}):
                system, user = load_prompts({"a": 1})
                self.assertEqual(system, "Custom system")
                self.assertIn('"a": 1', user)
                (root / "debug_template.txt").write_text("Missing placeholder")
                with self.assertRaises(ValueError):
                    load_prompts({})

    def test_persistence_recovery_and_delete_running(self):
        with tempfile.TemporaryDirectory() as d:
            store = JobStore(d)
            job_id = store.create("api", 1)
            with self.assertRaises(ValueError):
                store.delete(job_id)
            reopened = JobStore(d)
            reopened.recover()
            self.assertEqual(reopened.get(job_id)["status"], "failed")

    def test_logger_redacts_token(self):
        with tempfile.TemporaryDirectory() as d:
            log = configure_logging(d)
            with patch.dict(os.environ, {"DEBUG_AGENT_API_TOKEN": TOKEN}):
                log.info("token=%s", TOKEN)
            content = (Path(d) / "agent.jsonl").read_text()
            self.assertNotIn(TOKEN, content)
            self.assertIn("[REDACTED]", content)
            close_logging()
