"""Additional static diagnostics and portable report rendering."""
import ast
import hashlib
import html
import json
from pathlib import Path

def extra_checks(files):
    findings = []
    def add(file, node, rule, message):
        findings.append({"file": file, "line": getattr(node, "lineno", 1),
                         "severity": "warning", "rule": rule, "message": message,
                         "origin": "local static check"})
    for item in files:
        if not item["file"].endswith(".py"):
            continue
        try:
            tree = ast.parse(item["content"])
        except (SyntaxError, ValueError):
            continue
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = node.module + "." + alias.name
        def name(node):
            if isinstance(node, ast.Name):
                return aliases.get(node.id, node.id)
            if isinstance(node, ast.Attribute):
                return name(node.value) + "." + node.attr
            return ""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        add(item["file"], default, "PY_MUTABLE_DEFAULT",
                            "Mutable default argument can share state across calls; use None and initialize inside.")
            if not isinstance(node, ast.Call):
                continue
            call = name(node.func)
            keywords = {k.arg: k.value for k in node.keywords}
            if call.startswith("subprocess.") and call.split(".")[-1] in {"run", "Popen", "call", "check_call", "check_output"}:
                shell = keywords.get("shell")
                if isinstance(shell, ast.Constant) and shell.value is True:
                    add(item["file"], node, "PY_SHELL_TRUE",
                        "shell=True needs careful command quoting; prefer an argument list with shell=False.")
            verify = keywords.get("verify")
            if call.startswith(("requests.", "httpx.")) and isinstance(verify, ast.Constant) and verify.value is False:
                add(item["file"], node, "PY_TLS_DISABLED",
                    "TLS certificate verification is disabled.")
            if call in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
                add(item["file"], node, "PY_UNTRUSTED_DESERIALIZATION",
                    "Deserialization can execute code. Only load trusted inputs.")
            if call == "yaml.load" and "Loader" not in keywords:
                add(item["file"], node, "PY_YAML_LOADER",
                    "yaml.load has no explicit Loader; use safe_load for ordinary untrusted YAML.")
        for func in (n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)):
            # Ignore nested functions; their execution context is different.
            def walk_scope(node):
                yield node
                for child in ast.iter_child_nodes(node):
                    if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                        yield from walk_scope(child)
            for node in walk_scope(func):
                if isinstance(node, ast.Call) and name(node.func) in {
                    "time.sleep", "requests.get", "requests.post", "requests.put",
                    "requests.delete", "subprocess.run", "subprocess.call"}:
                    add(item["file"], node, "PY_ASYNC_BLOCKING",
                        "A synchronous call inside async code can block the event loop; use an async alternative or a worker.")
    return findings

def identify(findings, files):
    sources = {f["file"]: f["content"].splitlines() for f in files}
    for finding in findings:
        finding.setdefault("rule", "LOCAL_" + hashlib.sha256(finding["message"].encode()).hexdigest()[:10])
        line = finding.get("line") or 1
        lines = sources.get(finding["file"], [])
        snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
        value = json.dumps([finding["file"], finding["rule"], snippet])
        finding["fingerprint"] = hashlib.sha256(value.encode()).hexdigest()[:24]
    return findings

def compare(current, previous, scanned):
    if not isinstance(previous, dict) or not isinstance(previous.get("local_findings"), list):
        raise ValueError("Baseline must be a Debug Agent JSON report.")
    old = previous["local_findings"]
    if any(not isinstance(f, dict) or not f.get("fingerprint") for f in old):
        raise ValueError("Baseline needs v2 finding fingerprints; create a fresh baseline.")
    old_ids = {f["fingerprint"] for f in old}
    new_ids = {f["fingerprint"] for f in current}
    return {"new": [f for f in current if f["fingerprint"] not in old_ids],
            "resolved": [f for f in old if f["fingerprint"] not in new_ids and f["file"] in scanned],
            "not_rechecked": [f for f in old if f["file"] not in scanned],
            "unchanged": sum(f["fingerprint"] in old_ids for f in current)}

def render_html(result):
    esc = lambda x: html.escape(str(x), quote=True)
    rows = "".join("<tr><td>" + "</td><td>".join(esc(f[k]) for k in
                   ("severity", "file", "line", "message")) + "</td></tr>"
                   for f in result["local_findings"])
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Debug Agent Pro report</title>
<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#182033}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd3df;padding:10px;text-align:left}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:20px}
</style><h1>Debug Agent Pro</h1><p>""" + esc(result["created_at"]) + """</p>
<h2>Local findings</h2><table><tr><th>Severity</th><th>File</th><th>Line</th><th>Finding</th></tr>""" + rows + (
        "</table><h2>AI review (" + esc(result["ai_status"]) + ")</h2><pre>" + esc(result["report"]) +
        "</pre><h2>Scope and comparison</h2><pre>" +
        esc(json.dumps({k: result[k] for k in ("files", "skipped", "limitations", "comparison") if k in result}, indent=2)) +
        "</pre></html>")
