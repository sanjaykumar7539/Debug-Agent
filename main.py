"""Debug Agent Pro — bounded source review, offline checks, optional Gemini review."""
import argparse
import ast
import fnmatch
import json
import os
from pathlib import Path
import re
import sys
import time
import tokenize
import io
from features import extra_checks, identify, compare, render_html
from prompt_loader import load_prompts
from logger import get_logger, configure_logging
from memory import JobStore
import urllib.error
import urllib.request
from datetime import datetime, timezone

EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".h",
              ".cs", ".go", ".rs", ".php", ".rb", ".sh", ".ps1", ".sql", ".html",
              ".css", ".json", ".yaml", ".yml", ".toml", ".md", ".txt"}
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
        ".next", "debug_reports", ".idea", ".vscode", "workspace", "logs"}
SECRET = re.compile(
    r"AIza[0-9A-Za-z_-]{30,}|"
    r"(?i:(?:api[_-]?key|password|passwd|secret|access[_-]?token)\s*[:=]\s*)"
    r"[\"'][^\"'\r\n]{4,}[\"']"
)

def redact(text):
    text = SECRET.sub("[REDACTED_SECRET]", text)
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                  lambda m: "[REDACTED_PRIVATE_KEY]" + "\n" * m.group().count("\n"), text, flags=re.S)
    key = os.getenv("GEMINI_API_KEY", "")
    return text.replace(key, "[REDACTED_SECRET]") if key else text

def sensitive(path):
    name = path.name.lower()
    return (name.startswith(".env") or name.endswith((".pem", ".key", ".p12", ".pfx"))
            or name in {"credentials.json", "id_rsa", "id_ed25519"})

def read_text(path, limit):
    if path.stat().st_size > limit:
        raise ValueError("exceeds per-file byte limit")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("exceeds per-file byte limit")
    if b"\x00" in raw:
        raise ValueError("binary content")
    if path.suffix == ".py":
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding)
    return raw.decode("utf-8-sig")

def collect(target, max_files, max_bytes, max_total, excludes, blocked=()):
    root = target if target.is_dir() else target.parent
    selected, skipped = [], []
    total = 0
    def candidates():
        if target.is_file():
            yield target
            return
        for base, dirs, files in os.walk(target, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP
                             and not (Path(base) / d).is_symlink()
                             and (Path(base) / d).resolve() not in blocked
                             and not any(fnmatch.fnmatch((Path(base)/d).relative_to(root).as_posix(), p)
                                         for p in excludes))
            for name in sorted(files):
                yield Path(base) / name
    for path in candidates():
        rel = path.relative_to(root).as_posix()
        if path.resolve() in blocked:
            continue
        if path.is_symlink() or sensitive(path):
            skipped.append({"file": rel, "reason": "symlink or sensitive filename"})
            continue
        if path.suffix.lower() not in EXTENSIONS or any(fnmatch.fnmatch(rel, p) for p in excludes):
            continue
        if len(selected) >= max_files:
            skipped.append({"file": rel, "reason": "file-count limit reached; scan stopped"})
            break
        try:
            content = read_text(path, max_bytes)
        except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
            skipped.append({"file": rel, "reason": type(exc).__name__ + ": unreadable or oversized text"})
            continue
        size = len(content.encode("utf-8"))
        if total + size > max_total:
            skipped.append({"file": rel, "reason": "total byte limit"})
            continue
        total += size
        selected.append({"file": rel, "content": content})
    return selected, skipped

def local_checks(files):
    findings = []
    def add(file, line, severity, message):
        findings.append(dict(file=file, line=line, severity=severity, message=message,
                             origin="local static check"))
    for item in files:
        name, code = item["file"], item["content"]
        for match in SECRET.finditer(code):
            add(name, code.count("\n", 0, match.start()) + 1, "warning",
                "Possible hard-coded secret. Inspect and move real credentials to environment variables.")
        if name.endswith(".json"):
            try:
                json.loads(code)
            except json.JSONDecodeError as exc:
                add(name, exc.lineno, "error", "Invalid JSON: " + exc.msg)
        if not name.endswith(".py"):
            continue
        try:
            tree = ast.parse(code, filename=name)
            compile(tree, name, "exec")  # Compile only; never execute target code.
        except (SyntaxError, ValueError) as exc:
            add(name, getattr(exc, "lineno", 1), "error", str(getattr(exc, "msg", "Invalid Python syntax")))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                add(name, node.lineno, "warning", "Bare except also catches interruption and exit signals.")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    add(name, node.lineno, "warning", "Dynamic code execution: verify input trust.")
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    owner, method = node.func.value.id, node.func.attr
                    if owner == "requests" and method in {"get", "post", "put", "delete", "patch", "request"}:
                        if not any(k.arg == "timeout" for k in node.keywords):
                            add(name, node.lineno, "warning", "HTTP call has no explicit timeout (check any **kwargs).")
    return findings

def ai_review(payload, model, timeout=90, retries=2):
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        raise ValueError("Set GEMINI_API_KEY to a new API key, or use --offline.")
    model = model.removeprefix("models/")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", model):
        raise ValueError("Invalid model ID.")
    system_prompt, user_prompt = load_prompts(payload)
    log = get_logger()
    log.info("ai_request_started")
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {"maxOutputTokens": 8192}
    }).encode()
    req = urllib.request.Request(
        "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent",
        data=body, headers={"Content-Type": "application/json", "x-goog-api-key": key}, method="POST")
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 500, 502, 503, 504} and attempt < retries:
                log.warning("ai_request_retry attempt=%d", attempt + 1)
                time.sleep(2 ** attempt)
                continue
            messages = {400: "Request rejected; check model and input size.",
                        401: "API authentication failed.", 403: "API access denied.",
                        404: "Model unavailable. Set --model to an accessible model ID.",
                        429: "Rate limit or quota exceeded."}
            raise RuntimeError(messages.get(exc.code, "API request failed.") +
                               " HTTP " + str(exc.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt < retries:
                log.warning("ai_request_retry attempt=%d", attempt + 1)
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError("Network request failed or timed out.") from None
    if not isinstance(result, dict):
        raise RuntimeError("API returned an invalid response object.")
    candidates = result.get("candidates", [])
    if not candidates:
        raise RuntimeError("API returned no candidate; the request may have been blocked.")
    candidate = candidates[0]
    if not isinstance(candidate, dict):
        raise RuntimeError("API returned an invalid candidate.")
    text = "\n".join(p.get("text", "") for p in candidate.get("content", {}).get("parts", [])
                     if not p.get("thought", False)).strip()
    if not text:
        raise RuntimeError("API returned no report text.")
    if candidate.get("finishReason") not in {None, "STOP"}:
        text += "\n\nWARNING: Response may be incomplete. Finish reason: " + str(candidate["finishReason"])
    log.info("ai_request_completed")
    return redact(text)

def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="Source file or project folder")
    parser.add_argument("--version", action="version", version="Debug Agent Pro 3.0")
    parser.add_argument("--preview", action="store_true", help="Save redacted request preview; never call the API")
    parser.add_argument("--baseline", type=Path, help="Compare local findings against a previous v2 JSON report")
    parser.add_argument("--fail-on", choices=["none", "error", "warning"], default="none",
                        help="Exit 3 when local findings meet this severity")
    parser.add_argument("--offline", action="store_true", help="Local checks only; no API calls")
    parser.add_argument("--yes", action="store_true", help="Authorize sending selected, redacted code to Gemini")
    parser.add_argument("--model", default=os.getenv("GEMINI_MODEL", "gemini-3-flash-preview"))
    parser.add_argument("--context", default="", help="Expected behavior or problem description")
    parser.add_argument("--error-log", type=Path, help="Optional UTF-8 traceback/log file")
    parser.add_argument("--exclude", action="append", default=[], help="Relative glob to omit; repeatable")
    parser.add_argument("--max-files", type=positive, default=40)
    parser.add_argument("--max-file-kb", type=positive, default=64)
    parser.add_argument("--max-total-kb", type=positive, default=256)
    parser.add_argument("--output", type=Path, default=Path("debug_reports"))
    args = parser.parse_args(argv)
    log = configure_logging()
    log.info("cli_analysis_started")
    raw = args.path or input("Enter a source file or project folder: ")
    target = Path(raw.strip().strip('"').strip("'")).expanduser().absolute()
    if target.is_symlink() or not target.exists():
        parser.error("Target must be an existing, non-symlink file or directory.")
    excludes = list(args.exclude)
    ignore = (target if target.is_dir() else target.parent) / ".debugignore"
    if ignore.is_file() and not ignore.is_symlink():
        try:
            excludes += [line.strip() for line in read_text(ignore, 65536).splitlines()
                         if line.strip() and not line.lstrip().startswith("#")]
        except (OSError, UnicodeError, ValueError):
            parser.error("Cannot read .debugignore (UTF-8, maximum 64 KiB).")
    blocked = {args.output.resolve(), Path(os.getenv("DEBUG_AGENT_WORKSPACE", "workspace")).resolve(),
               Path(os.getenv("DEBUG_AGENT_LOG_DIR", "logs")).resolve()}
    if args.baseline:
        blocked.add(args.baseline.resolve())
    files, skipped = collect(target, args.max_files, args.max_file_kb * 1024,
                             args.max_total_kb * 1024, excludes, blocked)
    if not files:
        parser.error("No supported readable source files selected.")
    findings = identify(local_checks(files) + extra_checks(files), files)
    log.info("local_checks_completed files=%d findings=%d", len(files), len(findings))
    comparison = None
    if args.baseline:
        try:
            previous = json.loads(read_text(args.baseline, 8 * 1024 * 1024))
            comparison = compare(findings, previous, {f["file"] for f in files})
        except (OSError, UnicodeError, ValueError, KeyError, TypeError):
            parser.error("Invalid baseline: choose a v2 JSON report under 8 MiB.")
    print("Selected files:")
    for item in files:
        print("  " + item["file"])
    print(f"Local findings: {len(findings)} | Skipped entries: {len(skipped)}")
    payload = {"context": redact(args.context), "local_findings": findings,
               "files": [{"file": f["file"], "source": "\n".join(f"{i}: {line}" for i, line in enumerate(redact(f["content"]).splitlines(), 1))} for f in files],
               "omitted": skipped}
    if args.error_log:
        try:
            payload["error_log"] = redact(read_text(args.error_log, 64 * 1024))
        except (OSError, UnicodeError, ValueError, SyntaxError):
            parser.error("Error log must be readable text under 64 KiB.")
    report = "Offline mode: only Python syntax, JSON syntax and selected Python heuristics were checked."
    status, exit_code = "offline", 0
    if not args.offline and not args.preview:
        print("AI review sends selected source, context and log to Google Gemini. Redaction is best-effort.")
        authorized = args.yes or input("Send these files? [y/N]: ").strip().lower() == "y"
        if authorized:
            try:
                print("Analyzing...")
                report = ai_review(payload, args.model)
                status = "completed"
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
                report = "AI review failed: " + redact(str(exc))
                status, exit_code = "failed", 1
                log.warning("ai_review_failed error_type=%s", type(exc).__name__)
        else:
            status = "declined"
            report = "AI upload declined. Local static checks only."
    if args.preview:
        status, report = "preview", "Request preview only. No API call was made."
    result = {"version": "3.0", "created_at": datetime.now(timezone.utc).isoformat(), "ai_status": status,
              "model": args.model if status in {"completed", "failed"} else None,
              "files": [f["file"] for f in files], "skipped": skipped,
              "local_findings": findings, "report": report,
              "limitations": "No target execution, runtime testing, dependency audit or exhaustive analysis."}
    if comparison is not None:
        result["comparison"] = comparison
    result = json.loads(redact(json.dumps(result)))
    args.output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    base = args.output / ("review_" + stamp)
    if args.preview:
        base.with_suffix(".request.json").write_text(redact(json.dumps(payload, indent=2)), encoding="utf-8")
    base.with_suffix(".html").write_text(render_html(result), encoding="utf-8")
    base.with_suffix(".json").write_text(redact(json.dumps(result, indent=2)), encoding="utf-8")
    lines = ["# Debug Agent Pro report", "", "## Local static findings", ""]
    lines += [f"- {f['severity'].upper()}: {f['file']}:{f['line']} — {f['message']}" for f in findings]
    if not findings:
        lines += ["No issues detected by the limited local checks; this does not prove correctness."]
    lines += ["", "## AI review", "", report, "", "## Scope", "",
              result["limitations"], "", "Reviewed files:"] + ["- " + f["file"] for f in files]
    lines += ["", "Skipped entries:"] + ["- " + s["file"] + ": " + s["reason"] for s in skipped]
    base.with_suffix(".md").write_text(redact("\n".join(lines)), encoding="utf-8")
    if comparison is not None:
        with base.with_suffix(".md").open("a", encoding="utf-8") as stream:
            stream.write("\n\n## Baseline comparison\n\n" + redact(json.dumps(comparison, indent=2)))
        print(f"Comparison: {len(comparison['new'])} new, {len(comparison['resolved'])} resolved, "
              f"{len(comparison['not_rechecked'])} not rechecked")
    print("Reports saved: " + str(base.with_suffix(".md").resolve()))
    store = JobStore()
    job_id = store.create("cli", len(files))
    store.finish(job_id, "failed" if status == "failed" else "completed", result)
    print("History ID: " + job_id)
    log.info("cli_analysis_completed job_id=%s status=%s", job_id, status)
    if exit_code == 0 and args.fail_on != "none":
        if any(f["severity"] == "error" or args.fail_on == "warning" for f in findings):
            return 3
    return exit_code

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
    except (OSError, EOFError) as exc:
        print("Error: " + redact(str(exc)), file=sys.stderr)
        sys.exit(1)
