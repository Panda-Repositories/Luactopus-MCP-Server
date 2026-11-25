from __future__ import annotations

import difflib
import fnmatch
import json
import re
import shutil
from pathlib import Path
from typing import Any

from . import backends
from .config import settings
from .logs import action

TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".lua", ".luau", ".json", ".md", ".txt", ".cfg", ".toml",
            ".ini", ".yaml", ".yml", ".sh", ".bat", ".cmd", ".html", ".csv"}
SKIP_DIRS = {"__pycache__", ".git", "node_modules", "output", ".venv"}
MAX_READ = 200_000

SCOPED_FILES = {
    "ib3": ["deobfuscator.py"],
    "oxygen": ["l2.lua"],
}
FORK_IGNORE = shutil.ignore_patterns("__pycache__", ".git", "node_modules", "output", "*.log")


def _require_edits() -> None:
    if not settings.allow_tool_edits:
        raise PermissionError("tool editing is disabled (ALLOW_TOOL_EDITS=false)")


def _safe_join(root: Path, rel: str) -> Path:
    rel = (rel or "").replace("\\", "/").lstrip("/")
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        raise PermissionError("path escapes the tool folder")
    return p


def _scoped(b: backends.Backend) -> list[str] | None:
    return SCOPED_FILES.get(b.id)


def list_files(backend_id: str, subpath: str = "", pattern: str = "*", limit: int = 400) -> dict[str, Any]:
    b = backends.get(backend_id)
    root = b.root()
    base = _safe_join(root, subpath)
    files = []
    scoped = _scoped(b)
    if scoped:
        candidates = [root / f for f in scoped]
    else:
        candidates = [p for p in base.rglob("*") if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS)]
    for p in sorted(candidates):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if not fnmatch.fnmatch(p.name, pattern) and not fnmatch.fnmatch(rel, pattern):
            continue
        files.append({"path": rel, "bytes": p.stat().st_size, "text": p.suffix.lower() in TEXT_EXT})
        if len(files) >= limit:
            break
    return {"backend": b.id, "root": str(root), "override_active": b.has_override(), "entry": b.entry,
            "files": files, "truncated": len(files) >= limit}


def read_file(backend_id: str, path: str, offset: int = 1, limit: int = 400) -> dict[str, Any]:
    b = backends.get(backend_id)
    root = b.root()
    p = _safe_join(root, path)
    scoped = _scoped(b)
    if scoped and p.relative_to(root).as_posix() not in scoped:
        raise PermissionError(f"{backend_id} exposes only: {', '.join(scoped)}")
    if not p.is_file():
        raise FileNotFoundError(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    offset = max(1, offset)
    chunk = lines[offset - 1: offset - 1 + max(1, limit)]
    body = "\n".join(f"{i:>6}\t{line}" for i, line in enumerate(chunk, offset))
    if len(body) > MAX_READ:
        body = body[:MAX_READ] + "\n... (truncated)"
    return {"backend": b.id, "path": path, "from_override": b.has_override(), "total_lines": len(lines),
            "offset": offset, "lines_returned": len(chunk), "content": body}


def search(backend_id: str, regex: str, glob: str = "*", max_hits: int = 80) -> dict[str, Any]:
    b = backends.get(backend_id)
    rx = re.compile(regex)
    hits = []
    for f in list_files(backend_id, "", glob, limit=5000)["files"]:
        if not f["text"]:
            continue
        p = b.root() / f["path"]
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if rx.search(line):
                hits.append({"path": f["path"], "line": i, "text": line.strip()[:300]})
                if len(hits) >= max_hits:
                    return {"hits": hits, "truncated": True}
    return {"hits": hits, "truncated": False}


def fork(backend_id: str, force: bool = False) -> dict[str, Any]:
    _require_edits()
    b = backends.get(backend_id)
    if b.base == "custom":
        return {"backend": b.id, "note": "custom tools are edited in place", "root": str(b.original_root())}
    dst = b.override_root()
    if dst.exists():
        if not force:
            return {"backend": b.id, "override": str(dst), "note": "override already exists"}
        shutil.rmtree(dst)
    src = b.original_root()
    scoped = _scoped(b)
    if scoped:
        dst.mkdir(parents=True)
        for f in scoped:
            shutil.copy2(src / f, dst / f)
    else:
        shutil.copytree(src, dst, ignore=FORK_IGNORE)
    action("tool_forked", backend=b.id, src=str(src), dst=str(dst))
    return {"backend": b.id, "override": str(dst), "copied_from": str(src)}


def write_file(backend_id: str, path: str, content: str) -> dict[str, Any]:
    _require_edits()
    b = backends.get(backend_id)
    if b.base != "custom" and not b.has_override():
        fork(backend_id)
    root = b.override_root() if b.base != "custom" else b.original_root()
    p = _safe_join(root, path)
    p.parent.mkdir(parents=True, exist_ok=True)
    existed = p.exists()
    p.write_text(content, encoding="utf-8")
    action("tool_file_written", backend=b.id, path=str(p), bytes=len(content), existed=existed)
    return {"backend": b.id, "path": path, "written": str(p), "bytes": len(content), "created": not existed}


def edit_file(backend_id: str, path: str, old: str, new: str, replace_all: bool = False) -> dict[str, Any]:
    _require_edits()
    b = backends.get(backend_id)
    if b.base != "custom" and not b.has_override():
        fork(backend_id)
    root = b.override_root() if b.base != "custom" else b.original_root()
    p = _safe_join(root, path)
    if not p.is_file():
        raise FileNotFoundError(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    n = text.count(old)
    if n == 0:
        raise ValueError("old text not found (it must match exactly, including indentation)")
    if n > 1 and not replace_all:
        raise ValueError(f"old text occurs {n} times; add context or set replace_all=true")
    text = text.replace(old, new) if replace_all else text.replace(old, new, 1)
    p.write_text(text, encoding="utf-8")
    action("tool_file_edited", backend=b.id, path=str(p), replacements=n if replace_all else 1)
    return {"backend": b.id, "path": path, "replacements": n if replace_all else 1}


def diff(backend_id: str, max_chars: int = 60_000) -> dict[str, Any]:
    b = backends.get(backend_id)
    if not b.has_override():
        return {"backend": b.id, "override_active": False, "diff": ""}
    o, n = b.original_root(), b.override_root()
    chunks = []
    for p in sorted(n.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in TEXT_EXT or set(p.relative_to(n).parts) & SKIP_DIRS:
            continue
        rel = p.relative_to(n).as_posix()
        orig = o / rel
        a = orig.read_text(encoding="utf-8", errors="replace").splitlines(True) if orig.is_file() else []
        bb = p.read_text(encoding="utf-8", errors="replace").splitlines(True)
        if a != bb:
            chunks.append("".join(difflib.unified_diff(a, bb, f"original/{rel}", f"override/{rel}")))
    text = "\n".join(chunks)
    return {"backend": b.id, "override_active": True, "files_changed": len(chunks),
            "diff": text[:max_chars] + ("\n... (truncated)" if len(text) > max_chars else "")}


def reset(backend_id: str) -> dict[str, Any]:
    _require_edits()
    b = backends.get(backend_id)
    if not b.has_override():
        return {"backend": b.id, "removed": False}
    shutil.rmtree(b.override_root())
    action("tool_override_removed", backend=b.id)
    return {"backend": b.id, "removed": True}


CUSTOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,40}$")


def create_custom(name: str, language: str, code: str, description: str = "", family: str = "custom",
                  dynamic: bool = False) -> dict[str, Any]:
    if not settings.allow_custom_tools:
        raise PermissionError("custom tools are disabled (ALLOW_CUSTOM_TOOLS=false)")
    if not CUSTOM_RE.match(name):
        raise ValueError("name must be lowercase letters/digits/_/- (2-41 chars)")
    language = language.lower()
    entries = {"python": "main.py", "node": "main.js", "lua": "main.lua", "lune": "main.luau"}
    if language not in entries:
        raise ValueError(f"language must be one of {', '.join(entries)}")
    d = settings.custom_tools_dir / name
    d.mkdir(parents=True, exist_ok=True)
    (d / entries[language]).write_text(code, encoding="utf-8")
    meta = {"name": name, "language": language, "entry": entries[language], "description": description,
            "family": family, "dynamic": dynamic}
    (d / "tool.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    backends.load_custom_backends()
    action("custom_tool_created", backend="custom:" + name, language=language, bytes=len(code))
    return {"backend": "custom:" + name, "dir": str(d), "entry": entries[language],
            "contract": "invoked as: <runtime> <entry> <input.lua> <output.lua>; write the result to output.lua, "
                        "exit 0 on success"}
