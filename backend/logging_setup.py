"""
Logging configuration + per-request correlation IDs.

The app previously created a logger but never configured it, so `logger.debug`
was invisible and warnings arrived unformatted. `configure()` fixes that once at
startup; `request_id_var` carries an id through the async call stack so every log
line emitted while handling a request can be tied back to it (and to the id the
client sees in an error response).
"""
from __future__ import annotations

import contextvars
import json
import logging
import sys
import uuid

# Set per request by the HTTP middleware; empty outside a request (e.g. CLI).
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")

_CONFIGURED = False


def new_request_id() -> str:
    """Short, collision-resistant id — long enough to grep, short enough to read
    out loud from an error message."""
    return uuid.uuid4().hex[:12]


class _RequestIdFilter(logging.Filter):
    """Attach the current request id to every record so both formatters can use
    it without each call site passing it explicitly."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get() or "-"
        return True


class _JsonFormatter(logging.Formatter):
    """One JSON object per line — for container log collectors."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure(level: str = "INFO", *, json_output: bool = False) -> None:
    """Install a single stderr handler on the app logger. Idempotent, and leaves
    uvicorn's own loggers alone so its access log keeps its familiar format."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(_RequestIdFilter())
    handler.setFormatter(
        _JsonFormatter()
        if json_output
        else logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(request_id)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )

    app_logger = logging.getLogger("lakera_demo")
    app_logger.handlers.clear()
    app_logger.addHandler(handler)
    app_logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    # Ours is the only handler for these records — don't also hit the root logger
    # (which uvicorn configures) and print everything twice.
    app_logger.propagate = False

    _CONFIGURED = True
