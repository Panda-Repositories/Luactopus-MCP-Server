from __future__ import annotations

import json
import sys

from . import storage
from .config import settings
from .logs import auth_event, log, mask


def bootstrap() -> str | None:
    if not settings.protected_mode:
        return None
    if storage.active_key_count() > 0:
        return None
    key = storage.create_api_key("bootstrap")
    path = settings.storage_dir / "FIRST_API_KEY.txt"
    path.write_text(
        "Luactopus MCP - first API key (shown once; its hash is stored in SQLite)\n"
        f"{key}\n\n"
        "Copy it into your MCP client config, then DELETE this file.\n"
        "Manage keys: python -m luactopus_mcp keys list|create|revoke\n",
        encoding="utf-8")
    print(f"\n[Luactopus] PROTECTED_MODE is on. First API key created:\n  {key}\n"
          f"  (also written to {path} - delete it after copying)\n", file=sys.stderr, flush=True)
    auth_event("key_created", name="bootstrap", prefix=key[:10], via="bootstrap")
    return key


def check_stdio() -> None:
    if not settings.protected_mode:
        return
    who = storage.verify_api_key(settings.api_key)
    auth_event("stdio_check", ok=bool(who), key=mask(settings.api_key))
    if not who:
        print("[Luactopus] PROTECTED_MODE=true but LUACTOPUS_API_KEY is missing or invalid. "
              "Set it in the MCP client's env for this server.", file=sys.stderr, flush=True)
        raise SystemExit(3)
    log.info("stdio client authorised with key %s (%s)", who["prefix"], who["name"])


def _extract_key(headers: dict[str, str]) -> str | None:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return headers.get("x-api-key") or None


class APIKeyASGIMiddleware:

    OPEN_PATHS = {"/health"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        client = scope.get("client") or ("?", 0)
        path = scope.get("path", "")
        entry = {"method": scope.get("method"), "path": path, "client": f"{client[0]}:{client[1]}",
                 "user_agent": headers.get("user-agent")}

        if path == "/health":
            return await _json(send, 200, {"status": "ok", "protected": settings.protected_mode})

        if settings.protected_mode:
            key = _extract_key(headers)
            who = storage.verify_api_key(key)
            if not who:
                auth_event("http_denied", key=mask(key or ""), **entry)
                from .logs import write_event
                write_event("http", {**entry, "status": 401})
                return await _json(send, 401, {"error": "unauthorized",
                                               "hint": "send Authorization: Bearer <api key> or X-API-Key"})
            entry["key"] = who["prefix"]

        status_holder = {}

        async def _send(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            from .logs import write_event
            write_event("http", {**entry, "status": status_holder.get("status")})


async def _json(send, status: int, body: dict) -> None:
    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})
