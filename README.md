# Debug Agent Pro 3.0

A source-review assistant with an English CLI, optional Gemini analysis,
authenticated FastAPI service, editable prompts, rotating logs, and SQLite history.

This is a tested foundation for a small, single-operator service. It has not been
certified for unrestricted production traffic, multiple tenants, or multiple API
workers. It does not execute submitted code or automatically apply fixes.

## Quick start — Windows PowerShell

Extract the entire ZIP and open a terminal in Debug_Agent_Pro.

Python 3.11 or 3.12 is recommended (local verification used Python 3.12).
The CLI uses only the Python standard library:

    python main.py "D:\YourProject" --offline

Interactive file/folder selection:

    python main.py

Online review needs a NEW Gemini API key. Revoke the key exposed in the original
uploaded script. Do not put the replacement into source code.

    $env:GEMINI_API_KEY = "YOUR_NEW_KEY"
    $env:GEMINI_MODEL = "YOUR_AVAILABLE_MODEL_ID"
    python main.py "D:\YourProject"

The default model ID is retained from the original script
(gemini-3-flash-preview); its availability has not been live-tested.
Online review sends selected source, context and logs to Google Gemini after
confirmation. --yes authorizes that upload without the interactive prompt.
Your provider account's quota and billing settings apply.

## Start the API

Install the optional API dependencies and generate a local access token:

    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    $env:DEBUG_AGENT_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
    .\.venv\Scripts\python.exe serve.py

The API listens on http://127.0.0.1:8000 with one process.
Keep the token in the same PowerShell session to make requests. If using a second
terminal, set the same token there. No .env loader is installed; use environment
variables or your deployment secret manager.

Example in a second terminal where the same token has been set:

    $headers = @{ "X-API-Key" = $env:DEBUG_AGENT_API_TOKEN }
    $body = @{
        files = @(@{ name = "example.py"; content = "def broken(:" })
        online = $false
    } | ConvertTo-Json -Depth 5

    $result = Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -Headers $headers -ContentType "application/json" -Body $body
    $result | ConvertTo-Json -Depth 12

    Invoke-RestMethod -Uri "http://127.0.0.1:8000/debug-status" -Headers $headers

The API accepts source text and relative filenames, not server filesystem paths.
POST /analyze is synchronous: it returns the finished report and job ID.
Running jobs are visible through the history endpoint while another request runs.

| Endpoint | Purpose | Authentication |
| --- | --- | --- |
| GET /health | Service health and version | Public |
| POST /analyze | Review submitted source files | X-API-Key |
| GET /debug-status | Recent jobs, optional limit=1..100 | X-API-Key |
| GET /debug-status/{job_id} | Job state and saved report | X-API-Key |
| GET /reports/{job_id} | HTML report | X-API-Key |
| DELETE /history/{job_id} | Delete a finished history record | X-API-Key |
| GET /openapi.json | API schema for future frontend integration | X-API-Key |

To use online analysis, the server must have GEMINI_API_KEY configured and each
request must set both online=true and allow_cloud_upload=true. The API defaults
to offline. The server selects the model from GEMINI_MODEL.

API limits: 40 files, 64 KiB per source, 256 KiB total source, 1 MiB HTTP body,
8,000 characters of context, 16,000 characters of error log; two analyses at once;
60 authenticated requests/minute across the shared token. Excess requests return
429. Invalid payloads return 422, oversized bodies 413, upstream review failures
502 with local findings retained, and missing provider configuration 503.

## Project structure

| Path | Responsibility |
| --- | --- |
| main.py | CLI, selection, baseline comparison, reports, Gemini client |
| features.py | Additional Python checks, fingerprints, HTML |
| prompts/system_prompt.txt | Editable review role and instructions |
| prompts/debug_template.txt | Editable evidence wrapper |
| prompt_loader.py | Bounded prompt loading and placeholder validation |
| logger.py | Rotating metadata-only JSON logs |
| logs/ | Runtime log files |
| app.py / serve.py | API and local startup |
| memory.py | SQLite job-history operations |
| workspace/ | Persistent history database |
| .github/workflows/ci-test.yml | Linux/Windows test matrix |
| test_agent.py / test_v2.py / test_api.py | Regression and API tests |
| example_reports/ | Earlier before/after example reports |

## Prompts and logs

Edit prompt files without modifying Python. debug_template.txt must contain
exactly one {evidence} placeholder. Prompts are loaded for each AI call, resolved
relative to the application rather than the shell's working directory.
Set DEBUG_AGENT_PROMPT_DIR to use another administrator-controlled folder.

Logs contain timestamps, stages, retries, job IDs, counts and completion/failure
status. They do not contain source, request bodies, prompts, provider responses,
or model reasoning. Output uses rotating JSON lines, about 1 MB per file with
3 backups. Known configured credentials are redacted defensively.
Interactive prompts and report locations still print to the console.

## Workspace and memory

CLI and API save reports in workspace/history.sqlite3. Source text and full
request payloads are not stored in this database; reports may include AI code
suggestions. Protect the database and generated reports as project data.

History is persistent but is not automatically sent to the model or indexed for
RAG. Workspace is an organizational folder, not an operating-system sandbox.
No user code is run. Interrupted API jobs are marked failed when the service
restarts; there is no durable queue or automatic replay. Terminal history is
retained until deleted. SQLite deletion is not guaranteed forensic erasure.

Use these optional environment variables:

| Variable | Meaning |
| --- | --- |
| DEBUG_AGENT_API_TOKEN | API authentication token, at least 32 characters |
| GEMINI_API_KEY | Provider credential for online reviews |
| GEMINI_MODEL | Accessible provider model ID |
| DEBUG_AGENT_PROMPT_DIR | Prompt directory |
| DEBUG_AGENT_LOG_DIR | Log directory, default logs |
| DEBUG_AGENT_WORKSPACE | History directory, default workspace |

Run one API process per workspace/log directory. For a network deployment, add
TLS, infrastructure request timeouts, and identity-aware access at your reverse
proxy. The shared token grants access to all history; this is not tenant isolation.
The included launcher stays on localhost and disables access logs.
Multi-worker queues, cancellation, retention scheduling and RAG are not included.

## Existing CLI features

- Python syntax compilation without target execution; JSON syntax validation.
- Review hints for bare except, eval/exec, missing requests timeouts, mutable
  default arguments, shell=True, verify=False, risky deserialization, YAML loader
  omissions and blocking calls in async functions.
- Optional problem description and traceback context.
- Markdown, JSON and escaped HTML reports.
- Best-effort secret redaction and sensitive-file exclusion.
- Bounded folder selection; skips common dependency/build folders, symlinks,
  logs, workspace, binary files and oversized source files.
- Numbered source evidence for AI analysis.
- Prioritized AI findings and proposed fixes; no automatic source modification.

Example:

    python main.py "D:\MyProject" --error-log "D:\error.txt" --context "Video playback is slower than the original."

Preview without any API call:

    python main.py "D:\MyProject" --preview

Inspect *.request.json. It contains the redacted evidence payload; prompts and
generation settings are loaded separately. A later online run rereads the source.

Comparison:

    python main.py "D:\MyProject" --offline --baseline "D:\reports\review_previous.json"

Use a regular v2/v3 JSON report, not a request preview. Findings in omitted files
are marked not_rechecked. Fingerprints tolerate line shifts but identical findings
on identical source lines may share a fingerprint.

Exclusions and caps:

    python main.py "D:\MyProject" --exclude "private/*" --max-files 60 --max-file-kb 80 --max-total-kb 400

.debugignore accepts one relative fnmatch glob per line, with # comments and blank
lines ignored. It is not gitignore syntax and has no negation. Gitignore is not
interpreted. Use exclusions for additional private paths.

CI exit behavior:

    python main.py "D:\MyProject" --offline --fail-on error

Exit codes: 0 report generated (may contain findings), 1 API/I/O failure,
2 invalid input, 3 findings meeting --fail-on, 130 interrupted.

## Testing and CI

    python -m pip install -r requirements-dev.txt
    python -m unittest discover -p "test*.py" -v

CI runs on pushes and pull requests for Python 3.11/3.12 on Ubuntu and Windows.
Place this folder's CONTENTS at your Git repository root so .github is at root.
The workflow runs tests without Gemini credentials; it does not deploy.
No workflow has been pushed or executed on GitHub during this update.

See VERIFICATION.md for actual checks and remaining limits.
Tests are functional checks, not proof that all bugs or vulnerabilities are found.
The current test stack emits an upstream TestClient/httpx deprecation warning;
all tests complete successfully.

## Review limits

Static heuristics can produce false positives. Alias handling is basic and does
not track all reassignment. Other languages are sent for AI review but are not
compiled locally. Redaction cannot guarantee removal of every secret. AI fixes
need human review and project-specific tests. This tool does not perform
comprehensive dependency audits, execute submitted code, or guarantee correctness.

References:
- https://ai.google.dev/api/generate-content
- https://fastapi.tiangolo.com/advanced/events/
- https://fastapi.tiangolo.com/advanced/testing-events/
