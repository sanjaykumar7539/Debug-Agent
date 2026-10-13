import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import main

class AgentTests(unittest.TestCase):
    def test_syntax(self):
        result = main.local_checks([{"file": "bad.py", "content": "def broken(:"}])
        self.assertEqual(result[0]["severity"], "error")

    def test_compile_context(self):
        result = main.local_checks([{"file": "bad.py", "content": "return 1"}])
        self.assertEqual(result[0]["severity"], "error")

    def test_redaction(self):
        self.assertNotIn("supersecret", main.redact('password = "supersecret"'))
        self.assertEqual(main.redact("AIza" + "X" * 35), "[REDACTED_SECRET]")

    def test_collection(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".env").write_text("secret")
            (root / "ok.py").write_text("x=1")
            (root / "big.py").write_text("x" * 100)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "bad.js").write_text("bad")
            files, skipped = main.collect(root, 5, 20, 50, [])
            self.assertEqual([f["file"] for f in files], ["ok.py"])
            self.assertEqual(len(skipped), 2)

    def test_missing_key(self):
        with patch.dict(main.os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                main.ai_review({}, "test")

    def test_api_failure(self):
        error = main.urllib.error.HTTPError("url", 403, "denied", {}, None)
        with patch.dict(main.os.environ, {"GEMINI_API_KEY": "test"}):
            with patch("urllib.request.urlopen", side_effect=error):
                with self.assertRaisesRegex(RuntimeError, "403"):
                    main.ai_review({}, "test")

    def test_offline_report(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "bad.py"
            source.write_text("def broken(:")
            output = root / "reports"
            with patch("urllib.request.urlopen") as network:
                self.assertEqual(main.main([str(source), "--offline", "--output", str(output)]), 0)
                network.assert_not_called()
            self.assertEqual(len(list(output.glob("*.md"))), 1)
            self.assertEqual(len(list(output.glob("*.json"))), 1)

if __name__ == "__main__":
    unittest.main()
