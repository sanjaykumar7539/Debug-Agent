# Version 3.0 verification

Verified in Linux with Python 3.12:
- 30 automated tests passed, including the existing 18 regression tests.
- API health, authentication, offline analysis, status, report rendering, deletion.
- Cloud opt-in, missing provider credentials, simulated AI success/failure.
- Source/body limits, duplicate rejection, path validation, rate limiting.
- Validation errors do not echo submitted source.
- Submitted source marker absent from logs and stored report history.
- Prompt loading, missing-placeholder rejection, token redaction.
- SQLite persistence and interrupted-job recovery.
- Real Uvicorn HTTP server: health, authorized analysis, persisted status,
  unauthorized rejection; process shut down after verification.
- Existing before/after fixture verification: 5 findings, then 0 after correction.
- requirements-tested.txt records the full dependency set from the test environment.

Not verified:
- Real Gemini access, billing, model availability or output quality.
- Native Windows execution (Windows is configured in the CI matrix).
- Execution of the GitHub-hosted workflow.
- Public deployment, load/stress behavior or multi-user isolation.

Known test-environment note:
Starlette emits a TestClient/httpx deprecation warning; tests pass.

Workspace provides report history, not a code-execution sandbox or RAG engine.
