"""Authenticated single-process API. Submit text, never server filesystem paths."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import PurePosixPath
import secrets
import threading
import time

from fastapi import FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import main as engine
from features import extra_checks, identify, render_html
from logger import configure_logging, close_logging
from memory import JobStore

MAX_BODY = 1024 * 1024

class SourceFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=240)
    content: str = Field(max_length=65536)

    @field_validator("name")
    @classmethod
    def filename(cls, value):
        path = PurePosixPath(value)
        if (path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value
                or any(ord(c) < 32 for c in value)):
            raise ValueError("Use a relative source filename.")
        if path.suffix.lower() not in engine.EXTENSIONS or engine.sensitive(path):
            raise ValueError("Unsupported or sensitive filename.")
        return value

    @field_validator("content")
    @classmethod
    def text_content(cls, value):
        if "\x00" in value or len(value.encode("utf-8")) > 65536:
            raise ValueError("Source must be text under 64 KiB.")
        return value

class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    files: list[SourceFile] = Field(min_length=1, max_length=40)
    context: str = Field(default="", max_length=8000)
    error_log: str = Field(default="", max_length=16000)
    online: bool = False
    allow_cloud_upload: bool = False

    @model_validator(mode="after")
    def bounded(self):
        if sum(len(f.content.encode("utf-8")) for f in self.files) > 256 * 1024:
            raise ValueError("Total source limit is 256 KiB.")
        if len({f.name for f in self.files}) != len(self.files):
            raise ValueError("Duplicate filenames.")
        if self.online and not self.allow_cloud_upload:
            raise ValueError("Online review requires allow_cloud_upload=true.")
        return self

class BoundaryMiddleware:
    """Authenticate before buffering; bound streamed bodies and request rate."""
    def __init__(self, app, token, max_requests=60):
        self.app, self.token = app, token
        self.max_requests = max_requests
        self.window, self.count = time.monotonic(), 0
        self.lock = threading.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        if scope["path"] != "/health":
            supplied = headers.get(b"x-api-key", b"")
            if not secrets.compare_digest(supplied, self.token.encode()):
                return await JSONResponse({"detail": "Unauthorized"}, 401)(scope, receive, send)
            with self.lock:
                current = time.monotonic()
                if current - self.window >= 60:
                    self.window, self.count = current, 0
                self.count += 1
                limited = self.count > self.max_requests
            if limited:
                return await JSONResponse({"detail": "Rate limit exceeded"}, 429,
                                          headers={"Retry-After": "60"})(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY:
                return await JSONResponse({"detail": "Request too large"}, 413)(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False
        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        async def secure_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
                ])
            await send(message)
        await self.app(scope, bounded_receive, secure_send)

def create_app(token=None, workspace=None, log_dir=None, max_requests=60):
    token = token or os.getenv("DEBUG_AGENT_API_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("Set DEBUG_AGENT_API_TOKEN to a random token of at least 32 characters.")
    gate = threading.BoundedSemaphore(2)

    @asynccontextmanager
    async def lifespan(app):
        app.state.log = configure_logging(log_dir)
        app.state.store = JobStore(workspace)
        app.state.store.recover()
        app.state.log.info("api_started")
        try:
            yield
        finally:
            app.state.log.info("api_stopped")
            close_logging()

    app = FastAPI(title="Debug Agent Pro", version="3.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(BoundaryMiddleware, token=token, max_requests=max_requests)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI's default may echo source/credentials in validation input.
        return JSONResponse({"detail": [{"loc": e["loc"], "type": e["type"],
                                        "msg": "Invalid request value"} for e in exc.errors()]}, 422)

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "3.0"}

    @app.get("/openapi.json")
    def schema():
        return app.openapi()

    @app.post("/analyze")
    def analyze(request: AnalyzeRequest):
        if request.online and not os.getenv("GEMINI_API_KEY"):
            raise HTTPException(503, "Server Gemini key is not configured.")
        if not gate.acquire(blocking=False):
            raise HTTPException(429, "Two analyses are already running.")
        job_id = None
        try:
            store, log = app.state.store, app.state.log
            job_id = store.create("api", len(request.files))
            log.info("analysis_started job_id=%s files=%d online=%s", job_id, len(request.files), request.online)
            files = [{"file": f.name, "content": f.content} for f in request.files]
            findings = identify(engine.local_checks(files) + extra_checks(files), files)
            result = {"version": "3.0", "created_at": datetime.now(timezone.utc).isoformat(),
                      "ai_status": "offline", "files": [f["file"] for f in files],
                      "skipped": [], "local_findings": findings,
                      "report": "Local static checks only. No target code was executed.",
                      "limitations": "Static heuristics are not exhaustive; no runtime or dependency testing."}
            if request.online:
                payload = {"context": engine.redact(request.context),
                           "error_log": engine.redact(request.error_log),
                           "local_findings": findings,
                           "files": [{"file": f["file"], "source": "\n".join(
                               f"{i}: {line}" for i, line in enumerate(engine.redact(f["content"]).splitlines(), 1))}
                                     for f in files]}
                try:
                    result["report"] = engine.ai_review(payload, os.getenv("GEMINI_MODEL", "gemini-3-flash-preview"))
                    result["ai_status"] = "completed"
                except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
                    result["report"] = "AI review failed. Local findings are available."
                    result["ai_status"] = "failed"
                    log.warning("ai_review_failed job_id=%s error_type=%s", job_id, type(exc).__name__)
            result = json.loads(engine.redact(json.dumps(result)))
            status = "failed" if result["ai_status"] == "failed" else "completed"
            store.finish(job_id, status, result)
            log.info("analysis_finished job_id=%s status=%s findings=%d", job_id, status, len(findings))
            response = {"job_id": job_id, "status": status, "result": result}
            return JSONResponse(response, 502 if status == "failed" else 200)
        except Exception as exc:
            app.state.log.error("analysis_failed job_id=%s error_type=%s", job_id, type(exc).__name__)
            if job_id:
                app.state.store.finish(job_id, "failed", {"error": "Analysis failed."})
            raise HTTPException(500, "Analysis failed; check metadata logs.") from None
        finally:
            gate.release()

    @app.get("/debug-status")
    def history(limit: int = Query(20, ge=1, le=100)):
        return {"jobs": app.state.store.recent(limit)}

    def get_job(job_id):
        job = app.state.store.get(job_id)
        if job is None:
            raise HTTPException(404, "Unknown job ID.")
        return job

    @app.get("/debug-status/{job_id}")
    def status(job_id: str):
        return get_job(job_id)

    @app.get("/reports/{job_id}")
    def report(job_id: str):
        job = get_job(job_id)
        if not job["result"] or "local_findings" not in job["result"]:
            raise HTTPException(409, "Report is not available.")
        return HTMLResponse(render_html(job["result"]))

    @app.delete("/history/{job_id}")
    def delete(job_id: str):
        try:
            if not app.state.store.delete(job_id):
                raise HTTPException(404, "Unknown job ID.")
        except ValueError:
            raise HTTPException(409, "Job is still running.") from None
        return {"deleted": job_id}

    return app
