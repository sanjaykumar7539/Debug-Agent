import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import main
from features import extra_checks, identify, compare, render_html

class V2Tests(unittest.TestCase):
    def test_rules(self):
        code = """import requests as r
import subprocess
import pickle
import time
def bad(items=[]):
    subprocess.run("ls", shell=True)
    r.get("https://example.com", verify=False)
    pickle.loads(b"data")
async def task():
    time.sleep(2)
"""
        rules = {f["rule"] for f in extra_checks([{"file": "app.py", "content": code}])}
        self.assertEqual(rules, {"PY_MUTABLE_DEFAULT", "PY_SHELL_TRUE", "PY_TLS_DISABLED",
                                "PY_UNTRUSTED_DESERIALIZATION", "PY_ASYNC_BLOCKING"})

    def test_clean(self):
        code = "async def task():\n    def nested():\n        time.sleep(1)\n"
        self.assertEqual(extra_checks([{"file": "app.py", "content": code}]), [])

    def test_private_key_line_numbers(self):
        code = "-----BEGIN PRIVATE KEY-----\naaa\nbbb\n-----END PRIVATE KEY-----\nx=1"
        self.assertEqual(main.redact(code).count("\n"), code.count("\n"))
        self.assertNotIn("aaa", main.redact(code))

    def test_baseline_omitted_not_resolved(self):
        files = [{"file": "a.py", "content": "eval(x)"}]
        findings = identify(main.local_checks(files), files)
        result = compare([], {"local_findings": findings}, set())
        self.assertEqual(len(result["not_rechecked"]), 1)
        self.assertEqual(result["resolved"], [])
        self.assertEqual(len(compare([], {"local_findings": findings}, {"a.py"})["resolved"]), 1)

    def test_line_shift_keeps_fingerprint(self):
        a = [{"file": "a.py", "content": "eval(x)"}]
        b = [{"file": "a.py", "content": "\n\neval(x)"}]
        self.assertEqual(identify(main.local_checks(a), a)[0]["fingerprint"],
                         identify(main.local_checks(b), b)[0]["fingerprint"])

    def test_html_escaping(self):
        report = render_html({"created_at": "", "local_findings": [], "ai_status": "test",
                              "report": "<script>alert(1)</script>"})
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)

    def test_preview_and_exclusions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "app.py").write_text('password = "sensitive_value"\n')
            (root / "omit.py").write_text("broken(")
            (root / ".debugignore").write_text("omit.py")
            output = root / "custom_reports"
            output.mkdir()
            (output / "old.py").write_text("broken(")
            with patch("urllib.request.urlopen") as network:
                self.assertEqual(main.main([str(root), "--preview", "--output", str(output)]), 0)
                network.assert_not_called()
            preview = next(output.glob("*.request.json")).read_text()
            self.assertNotIn("sensitive_value", preview)
            payload = json.loads(preview)
            self.assertEqual([f["file"] for f in payload["files"]], ["app.py"])
            self.assertTrue(payload["files"][0]["source"].startswith("1:"))

    def test_ci_exit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "bad.py").write_text("def broken(:")
            self.assertEqual(main.main([str(root / "bad.py"), "--offline",
                                       "--fail-on", "error", "--output", str(root / "out")]), 3)

    def test_api_success_and_headers(self):
        response = {"candidates": [{"content": {"parts": [{"text": "Review complete"}]}, "finishReason": "STOP"}]}
        with patch.dict(main.os.environ, {"GEMINI_API_KEY": "dummy-test-key"}):
            with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(response).encode())) as call:
                self.assertEqual(main.ai_review({}, "test"), "Review complete")
                request = call.call_args.args[0]
                self.assertNotIn("dummy-test-key", request.full_url)
                self.assertEqual(request.get_header("X-goog-api-key"), "dummy-test-key")

    def test_retry(self):
        error = main.urllib.error.HTTPError("url", 429, "rate", {}, None)
        good = io.BytesIO(b'{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}')
        with patch.dict(main.os.environ, {"GEMINI_API_KEY": "dummy"}):
            with patch("urllib.request.urlopen", side_effect=[error, good]) as call, patch("time.sleep"):
                self.assertEqual(main.ai_review({}, "test"), "ok")
                self.assertEqual(call.call_count, 2)

    def test_empty_response(self):
        with patch.dict(main.os.environ, {"GEMINI_API_KEY": "dummy"}):
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b'{"candidates":[]}')):
                with self.assertRaises(RuntimeError):
                    main.ai_review({}, "test")

if __name__ == "__main__":
    unittest.main()
