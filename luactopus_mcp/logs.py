from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .config import settings

_lock = threading.Lock()
log = logging.getLogger("luactopus")

_SECRET_KEYS = {"api_key", "apikey", "authorization", "x-api-key", "token", "password", "secret"}


def setup_logging() -> None:
    settings.ensure_dirs()
    for sub in ("requests", "actions", "auth", "http"):
        (settings.log_dir / sub).mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(settings.log_level)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    fh = logging.handlers.RotatingFileHandler(
        settings.log_dir / "server.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    eh = logging.StreamHandler(sys.stderr)
    eh.setFormatter(fmt)
    eh.setLevel(settings.log_level)
    root.addHandler(eh)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _clip(value: Any, limit: int | None = None) -> Any:
    limit = limit or settings.log_max_field_chars
    if isinstance(value, str):
        if len(value) > limit:
            return value[:limit] + f"... <{len(value) - limit} more chars>"
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in _SECRET_KEYS:
                out[k] = mask(str(v))
            else:
                out[k] = _clip(v, limit)
        return out
    if isinstance(value, (list, tuple)):
        items = [_clip(v, limit) for v in list(value)[:200]]
        if len(value) > 200:
            items.append(f"<{len(value) - 200} more items>")
        return items
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _clip(repr(value), limit)


def mask(secret: str) -> str:
    if not secret:
        return ""
    return secret[:6] + "..." + secret[-4:] if len(secret) > 12 else "***"


def write_event(channel: str, event: dict[str, Any]) -> None:
    event = {"ts": _now(), **_clip(event)}
    path = settings.log_dir / channel / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"
    line = json.dumps(event, ensure_ascii=False, default=str)
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def action(kind: str, **fields: Any) -> None:
    write_event("actions", {"kind": kind, **fields})
    log.info("action %s %s", kind, {k: v for k, v in fields.items() if k in ("job_id", "backend", "path", "ok", "returncode", "seconds")})


def auth_event(kind: str, **fields: Any) -> None:
    write_event("auth", {"kind": kind, **fields})


class RequestLogMiddleware:

    async def __call__(self, ctx, call_next):
        rid = uuid.uuid4().hex[:12]
        started = time.perf_counter()
        method = getattr(ctx, "method", "?")
        params = getattr(ctx, "params", None)
        session = None
        try:
            session = ctx.session_id
        except Exception:
            pass
        headers = None
        try:
            h = ctx.headers
            if h:
                headers = {k: (mask(v) if k.lower() in _SECRET_KEYS else v) for k, v in dict(h).items()}
        except Exception:
            pass
        base = {"id": rid, "method": method, "request_id": str(getattr(ctx, "request_id", None)),
                "session": session}
        write_event("requests", {**base, "phase": "received", "params": params, "headers": headers})
        try:
            result = await call_next(ctx)
        except Exception as exc:
            write_event("requests", {**base, "phase": "error", "error": f"{type(exc).__name__}: {exc}",
                                     "seconds": round(time.perf_counter() - started, 3)})
            log.warning("request %s %s failed: %s", method, rid, exc)
            raise
        summary: Any = result
        try:
            if hasattr(result, "model_dump"):
                summary = result.model_dump(mode="json", exclude_none=True)
        except Exception:
            summary = repr(result)
        write_event("requests", {**base, "phase": "completed", "result": summary,
                                 "seconds": round(time.perf_counter() - started, 3)})
        return result
