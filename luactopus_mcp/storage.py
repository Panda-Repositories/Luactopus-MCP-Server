from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from .config import settings

_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    prefix      TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    last_used   TEXT,
    uses        INTEGER NOT NULL DEFAULT 0,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    job_id      TEXT,
    layer       INTEGER,
    backend     TEXT NOT NULL,
    detected    TEXT,
    features    TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    readability REAL,
    seconds     REAL,
    error       TEXT,
    override    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fingerprints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    family      TEXT NOT NULL,
    backend     TEXT,
    features    TEXT NOT NULL,
    source      TEXT
);
CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    job_id      TEXT,
    backend     TEXT,
    worked      INTEGER,
    notes       TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        con = sqlite3.connect(settings.db_path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()


def init_db() -> None:
    with connect() as con:
        con.executescript(SCHEMA)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def create_api_key(name: str = "default") -> str:
    key = "lct_" + secrets.token_urlsafe(32)
    with connect() as con:
        con.execute("INSERT INTO api_keys(name, prefix, key_hash, created_at) VALUES (?,?,?,?)",
                    (name, key[:10], _hash(key), _now()))
    return key


def verify_api_key(key: str | None) -> dict[str, Any] | None:
    if not key:
        return None
    h = _hash(key.strip())
    with connect() as con:
        rows = con.execute("SELECT * FROM api_keys WHERE revoked = 0").fetchall()
        for row in rows:
            if hmac.compare_digest(row["key_hash"], h):
                con.execute("UPDATE api_keys SET last_used = ?, uses = uses + 1 WHERE id = ?",
                            (_now(), row["id"]))
                return {"id": row["id"], "name": row["name"], "prefix": row["prefix"]}
    return None


def list_api_keys() -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute("SELECT id, name, prefix, created_at, last_used, uses, revoked FROM api_keys "
                           "ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def revoke_api_key(key_id: int) -> bool:
    with connect() as con:
        cur = con.execute("UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0", (key_id,))
        return cur.rowcount > 0


def active_key_count() -> int:
    with connect() as con:
        return con.execute("SELECT COUNT(*) FROM api_keys WHERE revoked = 0").fetchone()[0]


def record_run(*, job_id: str | None, layer: int | None, backend: str, detected: str | None,
               features: list[str], ok: bool, readability: float | None, seconds: float | None,
               error: str | None, override: bool) -> None:
    with connect() as con:
        con.execute(
            "INSERT INTO runs(ts, job_id, layer, backend, detected, features, ok, readability, seconds, error,"
            " override) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (_now(), job_id, layer, backend, detected, json.dumps(sorted(features)), int(ok), readability,
             seconds, (error or "")[:2000], int(override)))


def run_history(limit: int = 2000) -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["features"] = json.loads(d["features"])
        out.append(d)
    return out


def add_fingerprint(family: str, backend: str | None, features: list[str], source: str | None) -> int:
    with connect() as con:
        cur = con.execute("INSERT INTO fingerprints(ts, family, backend, features, source) VALUES (?,?,?,?,?)",
                          (_now(), family, backend, json.dumps(sorted(features)), source))
        return int(cur.lastrowid)


def fingerprints() -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute("SELECT * FROM fingerprints ORDER BY id").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["features"] = json.loads(d["features"])
        out.append(d)
    return out


def delete_fingerprint(fp_id: int) -> bool:
    with connect() as con:
        return con.execute("DELETE FROM fingerprints WHERE id = ?", (fp_id,)).rowcount > 0


def add_feedback(job_id: str | None, backend: str | None, worked: bool | None, notes: str) -> int:
    with connect() as con:
        cur = con.execute("INSERT INTO feedback(ts, job_id, backend, worked, notes) VALUES (?,?,?,?,?)",
                          (_now(), job_id, backend, None if worked is None else int(worked), notes))
        return int(cur.lastrowid)


def stats() -> dict[str, Any]:
    with connect() as con:
        per_backend = con.execute(
            "SELECT backend, COUNT(*) AS runs, SUM(ok) AS ok, AVG(readability) AS avg_readability, "
            "AVG(seconds) AS avg_seconds FROM runs GROUP BY backend ORDER BY runs DESC").fetchall()
        n_fp = con.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0]
        n_fb = con.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        recent_fb = con.execute("SELECT * FROM feedback ORDER BY id DESC LIMIT 10").fetchall()
    return {
        "backends": [dict(r) for r in per_backend],
        "fingerprints": n_fp,
        "feedback_entries": n_fb,
        "recent_feedback": [dict(r) for r in recent_fb],
    }
