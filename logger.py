"""Rotating, metadata-only application logs. Never log code or request bodies."""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import threading
from datetime import datetime, timezone

_LOCK = threading.Lock()

class JsonFormatter(logging.Formatter):
    def format(self, record):
        message = record.getMessage()
        for key in ("GEMINI_API_KEY", "DEBUG_AGENT_API_TOKEN"):
            value = os.getenv(key, "")
            if value:
                message = message.replace(value, "[REDACTED]")
        return json.dumps({"time": datetime.now(timezone.utc).isoformat(),
                           "level": record.levelname, "event": message})

def get_logger():
    return logging.getLogger("debug_agent")

def configure_logging(directory=None):
    folder = Path(directory or os.getenv("DEBUG_AGENT_LOG_DIR", "logs")).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "agent.jsonl"
    with _LOCK:
        log = get_logger()
        log.setLevel(logging.INFO)
        log.propagate = False
        if any(getattr(h, "baseFilename", None) == str(path) for h in log.handlers):
            return log
        for handler in list(log.handlers):
            log.removeHandler(handler)
            handler.close()
        handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(JsonFormatter())
        log.addHandler(handler)
        return log

def close_logging():
    with _LOCK:
        log = get_logger()
        for handler in list(log.handlers):
            log.removeHandler(handler)
            handler.close()
